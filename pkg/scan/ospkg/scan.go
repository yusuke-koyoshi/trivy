package ospkg

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/xerrors"

	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner interface {
	Scan(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Result, bool, error)
}

type scanner struct {
	opts []ospkgDetector.Option
}

// NewScanner creates a new OS package scanner.
// The given options are forwarded to ospkgDetector.NewDetector during Scan.
func NewScanner(opts ...ospkgDetector.Option) Scanner {
	return &scanner{opts: opts}
}

func (s *scanner) Scan(ctx context.Context, target types.ScanTarget, opts types.ScanOptions) (types.Result, bool, error) {
	if !target.OS.Detected() {
		log.Debug("Detected OS: unknown")
		return types.Result{}, false, nil
	}
	log.Info("Detected OS", log.String("family",
		string(target.OS.Family)), log.String("version", target.OS.Name))

	// Skip OS package scanning if the target is expected not to have OS packages
	if !target.OS.Family.HasOSPackages() {
		log.Debug("Skipping OS package scanning", log.String("family", string(target.OS.Family)))
		return types.Result{}, false, nil
	}

	if target.OS.Extended {
		// TODO: move the logic to each detector
		target.OS.Name += "-ESM"
	}

	result := types.Result{
		Target: fmt.Sprintf("%s (%s %s)", target.Name, target.OS.Family, target.OS.Name),
		Class:  types.ClassOSPkg,
		Type:   target.OS.Family,
	}

	sort.Sort(target.Packages)

	// In-place mutation of target.Packages is visible both in the SBOM
	// (result.Packages shares the slice) and to the vuln suppression
	// step below.
	if running := target.RunningKernelRelease; running != "" {
		log.Info("Detected running kernel", log.String("release", running))
		labelKernelPackagesWith(target.Packages, target.OS.Family, running)
	}

	result.Packages = target.Packages

	if !opts.Scanners.Enabled(types.VulnerabilityScanner) {
		// Return packages only
		return result, false, nil
	}

	detector, err := ospkgDetector.NewDetector(target, s.opts...)
	if err != nil {
		return result, false, xerrors.Errorf("unable to initialize Detector for OS packages: %w", err)
	}

	vulns, eosl, err := detector.Detect(ctx)
	if err != nil {
		// Return a result for those who want to override the error handling.
		return result, false, xerrors.Errorf("failed vulnerability detection of OS packages: %w", err)
	}

	// Drop vulns belonging to inactive kernel packages so the report only
	// surfaces issues that affect the kernel currently running. Active=nil
	// packages (e.g. unknown running kernel, non-kernel packages) are
	// always retained.
	vulns = suppressInactiveKernelVulns(vulns, target.Packages)

	result.Vulnerabilities = vulns

	return result, eosl, nil
}
