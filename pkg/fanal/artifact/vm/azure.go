package vm

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	lru "github.com/hashicorp/golang-lru/v2"
	azurediskfile "github.com/yusuke-koyoshi/go-azure-managed-disks-file"
	"github.com/yusuke-koyoshi/go-azure-managed-disks-file/snapshot"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// In blocks of the library's 1 MiB default size, so up to 256 MiB of memory.
const storageAzureCacheSize = 256

const azureArtifactVersion = 0

const maxConcurrentAzureBlocks = 8

// Azure represents an artifact for Azure managed disk snapshots
type Azure struct {
	Storage
	logger     *log.Logger
	resourceID string
	cred       azcore.TokenCredential
	options    snapshot.Options
	stats      *azureAPIStats
}

func newAzure(resourceID string, vm Storage, sasDuration time.Duration) (*Azure, error) {
	// The default chain lets environment variables, an Azure CLI login and a
	// managed identity all work without flags of our own.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, xerrors.Errorf("Azure credential error: %w", err)
	}

	logger := log.WithPrefix("azure")
	stats := newAzureAPIStats(logger)
	return &Azure{
		Storage:    vm,
		logger:     logger,
		resourceID: resourceID,
		cred:       cred,
		options: snapshot.Options{
			Duration: sasDuration,
			Open: azurediskfile.OpenOptions{
				MaxConcurrentBlocks: maxConcurrentAzureBlocks,
			},
			PerRetryPolicies: []policy.Policy{stats},
		},
		stats: stats,
	}, nil
}

func (a *Azure) Inspect(ctx context.Context) (artifact.Reference, error) {
	// Deferred first so that the summary runs after the revocation deferred
	// below and counts its attempts.
	defer a.stats.logSummary()

	// The resource ID comes back when a snapshot is recreated under the same
	// name, so the cache is keyed by the uniqueId as well.
	uniqueID, err := snapshot.UniqueID(ctx, a.cred, a.resourceID, a.options)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("Azure snapshot error: %w", err)
	}
	// Azure resource IDs are case-insensitive, so differently cased IDs of the
	// same snapshot share the cache.
	cacheKey, err := a.calcCacheKey(strings.ToLower(a.resourceID) + "@" + uniqueID)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("cache key calculation error: %w", err)
	}

	// Checked before the grant, which takes seconds.
	if a.hasCache(ctx, cacheKey) {
		return a.reference(cacheKey), nil
	}

	// An expired SAS fails the remaining reads with 403 in the middle of the
	// scan. The time left, not the whole timeout, is what the SAS must outlast.
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) > a.options.Duration {
		a.logger.Warn("The SAS may expire before the scan times out",
			log.Duration("azure_sas_duration", a.options.Duration), log.Duration("time_left", time.Until(deadline)))
	}

	c, err := lru.New[string, []byte](storageAzureCacheSize)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("lru cache error: %w", err)
	}
	sr, cleanup, err := snapshot.GrantAccessAndOpenWithOptions(ctx, a.cred, a.resourceID, c, a.options)
	if errors.Is(err, snapshot.ErrSnapshotInUse) {
		return artifact.Reference{}, xerrors.Errorf("Azure snapshot open error: %w; "+
			"another scan or an export may be reading it. If neither is running, a failed scan left its SAS behind: "+
			"revoke it with 'az snapshot revoke-access' or wait until it expires", err)
	} else if err != nil {
		return artifact.Reference{}, xerrors.Errorf("Azure snapshot open error: %w", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			a.logger.Warn("Failed to revoke the snapshot SAS; it stays valid until it expires", log.Err(err))
		}
	}()

	// The snapshot can be recreated between the first lookup and the grant,
	// which would store the result of the new snapshot under the old key.
	info, err := snapshot.Describe(ctx, a.cred, a.resourceID, a.options)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("Azure snapshot error: %w", err)
	}
	if info.UniqueID != uniqueID {
		return artifact.Reference{}, xerrors.Errorf("Azure snapshot %s was recreated during the scan", a.resourceID)
	}
	a.logger.Debug("Snapshot described", log.Int("logical_sector_size", info.LogicalSectorSize))

	// Detection from the partition table misses MBR disks with 4096-byte sectors.
	blobInfo, err := a.analyze(ctx, sr, info.LogicalSectorSize)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("inspection error: %w", err)
	}

	if err = a.cache.PutBlob(ctx, cacheKey, blobInfo); err != nil {
		return artifact.Reference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	return a.reference(cacheKey), nil
}

func (a *Azure) reference(cacheKey string) artifact.Reference {
	return artifact.Reference{
		Name:    a.resourceID,
		Type:    types.TypeVM,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}
}

func (a *Azure) Clean(_ artifact.Reference) error {
	return nil
}

func (a *Azure) calcCacheKey(key string) (string, error) {
	s, err := cache.CalcKey(key, azureArtifactVersion, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("failed to calculate cache key: %w", err)
	}
	return s, nil
}

func (a *Azure) hasCache(ctx context.Context, cacheKey string) bool {
	_, missingCacheKeys, err := a.cache.MissingBlobs(ctx, cacheKey, []string{cacheKey})
	if err != nil {
		a.logger.Debug("Unable to query missing cache", log.Err(err))
		return false
	}

	if len(missingCacheKeys) == 0 {
		return true
	}

	a.logger.Debug("Missing virtual machine cache", log.String("key", cacheKey))
	return false
}
