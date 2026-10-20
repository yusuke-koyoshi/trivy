package vm_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yusuke-koyoshi/go-azure-managed-disks-file/snapshot"

	"github.com/aquasecurity/trivy/internal/cachetest"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
)

const azureSnapshotID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/snap"

// fakeAzure serves the ARM snapshot API and the blob behind the granted SAS.
type fakeAzure struct {
	// uniqueIDs answers the snapshot lookups in order; the last one repeats.
	uniqueIDs []string
	diskState armcompute.DiskState
	getErr    bool
	// failReads answers every range read with 404, which is not retried.
	failReads bool

	gets    atomic.Int64
	grants  atomic.Int64
	revokes atomic.Int64
}

func (f *fakeAzure) transport(t *testing.T) policy.Transporter {
	data := make([]byte, 4096)
	blob := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.Header().Set("x-ms-blob-type", "PageBlob")
		case r.URL.Query().Get("comp") == "pagelist":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?><PageList />`)
		case f.failReads:
			http.Error(w, "not found", http.StatusNotFound)
		default:
			var start, end int
			if _, err := fmt.Sscanf(r.Header.Get("x-ms-range"), "bytes=%d-%d", &start, &end); err != nil {
				http.Error(w, "unexpected range", http.StatusBadRequest)
				return
			}
			end = min(end, len(data)-1)
			sum := md5.Sum(data[start : end+1])
			w.Header().Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data[start : end+1])
		}
	}))
	t.Cleanup(blob.Close)
	sas := blob.URL + "/md-test/abcd?sv=test&sig=test"

	arm := fake.NewSnapshotsServerTransport(&fake.SnapshotsServer{
		Get: func(context.Context, string, string, *armcompute.SnapshotsClientGetOptions) (resp azfake.Responder[armcompute.SnapshotsClientGetResponse], errResp azfake.ErrorResponder) {
			n := int(f.gets.Add(1))
			if f.getErr {
				errResp.SetResponseError(http.StatusNotFound, "ResourceNotFound")
				return
			}
			id := f.uniqueIDs[min(n, len(f.uniqueIDs))-1]
			props := &armcompute.SnapshotProperties{UniqueID: &id}
			if f.diskState != "" {
				props.DiskState = &f.diskState
			}
			resp.SetResponse(http.StatusOK, armcompute.SnapshotsClientGetResponse{
				Snapshot: armcompute.Snapshot{Properties: props},
			}, nil)
			return
		},
		BeginGrantAccess: func(context.Context, string, string, armcompute.GrantAccessData, *armcompute.SnapshotsClientBeginGrantAccessOptions) (resp azfake.PollerResponder[armcompute.SnapshotsClientGrantAccessResponse], errResp azfake.ErrorResponder) {
			f.grants.Add(1)
			resp.SetTerminalResponse(http.StatusOK, armcompute.SnapshotsClientGrantAccessResponse{
				AccessURI: armcompute.AccessURI{AccessSAS: &sas},
			}, nil)
			return
		},
		BeginRevokeAccess: func(context.Context, string, string, *armcompute.SnapshotsClientBeginRevokeAccessOptions) (resp azfake.PollerResponder[armcompute.SnapshotsClientRevokeAccessResponse], errResp azfake.ErrorResponder) {
			f.revokes.Add(1)
			resp.SetTerminalResponse(http.StatusOK, armcompute.SnapshotsClientRevokeAccessResponse{}, nil)
			return
		},
	})
	return &hostRouter{blobHost: blob.Listener.Addr().String(), arm: arm}
}

// hostRouter sends the requests for the blob to its test server and the rest
// to the fake ARM server.
type hostRouter struct {
	blobHost string
	arm      policy.Transporter
}

func (r *hostRouter) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Host != r.blobHost {
		return r.arm.Do(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// readingWalker reads the disk once and, like the VM walker with a failed
// partition, carries on whatever the read returns.
type readingWalker struct {
	mockWalker
}

func (w *readingWalker) Walk(r *io.SectionReader, root string, opt walker.Option, fn walker.WalkFunc) error {
	_, _ = r.ReadAt(make([]byte, 512), 0)
	return w.mockWalker.Walk(r, root, opt, fn)
}

func inspectAzure(t *testing.T, c cache.ArtifactCache, f *fakeAzure) (artifact.Reference, string, error) {
	t.Helper()
	w := &readingWalker{mockWalker{root: "testdata/alpine"}}
	a, err := vm.NewArtifact(vm.TypeAzure.Prefix()+azureSnapshotID, c, w, artifact.Option{})
	require.NoError(t, err)
	azure, ok := a.(*vm.Azure)
	require.True(t, ok)

	var buf bytes.Buffer
	vm.SetAzureClient(azure, &azfake.TokenCredential{}, f.transport(t), log.New(log.NewHandler(&buf, nil)))
	ref, err := a.Inspect(t.Context())
	return ref, buf.String(), err
}

func TestAzure_Inspect(t *testing.T) {
	t.Run("cache miss, cache hit, then a recreated snapshot", func(t *testing.T) {
		c := cachetest.NewCache(t, nil)

		f := &fakeAzure{uniqueIDs: []string{"uid-1"}}
		got, logs, err := inspectAzure(t, c, f)
		require.NoError(t, err)
		assert.Equal(t, azureSnapshotID, got.Name)
		assert.Equal(t, []string{got.ID}, got.BlobIDs)
		cachetest.AssertBlobs(t, c, []cachetest.WantBlob{{ID: got.ID, BlobInfo: expectedBlobInfo}})
		// Looked up for the cache key, for the state right before the grant
		// and again after the grant.
		assert.Equal(t, int64(3), f.gets.Load())
		assert.Equal(t, int64(1), f.grants.Load())
		assert.Equal(t, int64(1), f.revokes.Load())
		// The summary runs after the revocation, so it counts its attempts.
		assert.Contains(t, logs, "get_snapshot_attempts=3")
		assert.Contains(t, logs, "revoke_access_attempts=1")

		f = &fakeAzure{uniqueIDs: []string{"uid-1"}}
		hit, logs, err := inspectAzure(t, c, f)
		require.NoError(t, err)
		assert.Equal(t, got, hit)
		assert.Equal(t, int64(0), f.grants.Load(), "no SAS for a cached result")
		assert.Equal(t, int64(0), f.revokes.Load())
		assert.Contains(t, logs, "get_snapshot_attempts=1")

		// The same resource ID with a new uniqueId is a different disk.
		f = &fakeAzure{uniqueIDs: []string{"uid-2"}}
		recreated, _, err := inspectAzure(t, c, f)
		require.NoError(t, err)
		assert.NotEqual(t, got.ID, recreated.ID)
		assert.Equal(t, int64(1), f.grants.Load())
	})

	t.Run("snapshot recreated during the scan", func(t *testing.T) {
		c := cachetest.NewCache(t, nil)
		f := &fakeAzure{uniqueIDs: []string{"uid-1", "uid-2"}}
		_, _, err := inspectAzure(t, c, f)
		require.ErrorContains(t, err, "was recreated during the scan")
		assert.Equal(t, int64(1), f.revokes.Load(), "the SAS is revoked on failure")
		cachetest.AssertBlobs(t, c, nil)
	})

	t.Run("disk read fails", func(t *testing.T) {
		c := cachetest.NewCache(t, nil)
		f := &fakeAzure{uniqueIDs: []string{"uid-1"}, failReads: true}
		_, _, err := inspectAzure(t, c, f)
		require.ErrorContains(t, err, "disk read error")
		assert.Equal(t, int64(1), f.revokes.Load())
		cachetest.AssertBlobs(t, c, nil)
	})

	t.Run("snapshot in use by another reader", func(t *testing.T) {
		c := cachetest.NewCache(t, nil)
		f := &fakeAzure{uniqueIDs: []string{"uid-1"}, diskState: armcompute.DiskStateActiveSAS}
		_, _, err := inspectAzure(t, c, f)
		require.ErrorIs(t, err, snapshot.ErrSnapshotInUse)
		assert.Equal(t, int64(0), f.grants.Load())
		assert.Equal(t, int64(0), f.revokes.Load(), "the SAS of the other reader is left alone")
	})

	t.Run("snapshot lookup fails", func(t *testing.T) {
		c := cachetest.NewCache(t, nil)
		f := &fakeAzure{getErr: true}
		_, _, err := inspectAzure(t, c, f)
		require.ErrorContains(t, err, "Azure snapshot error")
		assert.Equal(t, int64(0), f.grants.Load())
	})
}
