package ospkg

import (
	"slices"
	"sync"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/fanal/kernel"
	"github.com/aquasecurity/trivy/pkg/fanal/kernel/classifier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/types"
)

// cachedRunning holds the host's `uname -r` value for the lifetime of
// the trivy process. The host kernel does not change mid-process, so a
// long-running scan such as `trivy k8s` reads /proc/sys/kernel/osrelease
// at most once. Errors (non-Linux, /proc unavailable) are also cached so
// the warning path stays cheap.
var cachedRunning = sync.OnceValues(kernel.Running)

// labelKernelPackages reads the running kernel release of the host and
// labels matching packages with Active=true / Active=false in place. See
// labelKernelPackagesWith for the cross-match semantics.
//
// The cross-match between running release and classifier release strings
// is what implicitly distinguishes "scanning the live host" from "scanning
// an extracted rootfs of a different host" — when the target rootfs has no
// kernel package matching the host's `uname -r`, all kernels stay Active=nil.
func labelKernelPackages(pkgs ftypes.Packages, family ftypes.OSType) {
	if !hasKernelPackage(pkgs, family) {
		// No kernel packages in target — nothing to label and no point in
		// reading /proc. This skips the cachedRunning() call for container
		// images that lack a kernel binary (the common case), partial rootfs
		// scans without a package DB, and any artifact with zero OS packages.
		return
	}
	running, err := cachedRunning()
	if err != nil || running == "" {
		// Non-Linux build, /proc unavailable, or empty osrelease. Cannot
		// determine the running kernel; leave all packages with Active=nil.
		// We deliberately do NOT log here: this fires once per scan target
		// and on non-Linux builds (Windows/macOS CI) it would be noise.
		return
	}
	labelKernelPackagesWith(pkgs, family, running)
}

// hasKernelPackage reports whether pkgs contains at least one kernel package
// recognized by the family-specific classifier.
func hasKernelPackage(pkgs ftypes.Packages, family ftypes.OSType) bool {
	for _, pkg := range pkgs {
		if classifier.Classify(pkg, family).IsKernel {
			return true
		}
	}
	return false
}

// labelKernelPackagesWith is the testable core of labelKernelPackages.
// It takes the running kernel release string explicitly so the caller can
// supply it from any source (live host, dmesg banner, test fixture).
//
// Strategy:
//  1. Run the family-aware classifier over each package; collect every
//     kernel-related package along with its candidate release string.
//  2. Among kernel packages, mark Active=true on those whose release
//     matches `running`. When multiple entries share the same identity
//     (Name+Version+Release+Arch) but differ in Epoch — the AL2023
//     transition case — keep only the highest-Epoch one as Active=true and
//     demote the rest to Active=false.
//  3. Mark Active=false on every other kernel package (i.e. those whose
//     release does not match `running`). Sibling packages from different
//     Names that share the matching release (e.g. linux-image-X and
//     linux-headers-X) are all Active=true independently.
//  4. If no package matches `running`, every kernel package is left with
//     Active=nil. This is the safe fallback that mirrors pre-feature
//     behavior on extracted rootfs / unknown-running-kernel scans.
func labelKernelPackagesWith(pkgs ftypes.Packages, family ftypes.OSType, running string) {
	if running == "" {
		return
	}

	// Identity key used to detect "same package, different Epoch" — the
	// AL2023 epoch=0/epoch=1 duplicate scenario.
	type identityKey struct {
		name, version, release, arch string
	}

	type entry struct {
		idx     int
		key     identityKey
		matches bool
	}

	var entries []entry
	maxEpochByID := make(map[identityKey]int)
	anyMatch := false

	for i, pkg := range pkgs {
		r := classifier.Classify(pkg, family)
		if !r.IsKernel {
			continue
		}
		// Without a release string we cannot prove this kernel is *not* the
		// running one, so leaving it out of the entry set keeps Active=nil and
		// preserves its CVEs. Demoting it to Active=false (the alternative)
		// would silently suppress vulns for what may actually be the running
		// kernel — a false-negative we explicitly avoid.
		if r.Release == "" {
			continue
		}
		e := entry{
			idx: i,
			key: identityKey{pkg.Name, pkg.Version, pkg.Release, pkg.Arch},
		}
		if r.Matches(running) {
			e.matches = true
			anyMatch = true
			if cur, ok := maxEpochByID[e.key]; !ok || pkg.Epoch > cur {
				maxEpochByID[e.key] = pkg.Epoch
			}
		}
		entries = append(entries, e)
	}

	if !anyMatch {
		// Running kernel not represented in the package set; fall back to
		// "everything Active=nil" to preserve current behavior.
		return
	}

	for _, e := range entries {
		active := e.matches && pkgs[e.idx].Epoch == maxEpochByID[e.key]
		pkgs[e.idx].Active = lo.ToPtr(active)
	}
}

// suppressInactiveKernelVulns removes vulnerabilities whose parent package
// has Active=false. Vulns from Active=true and Active=nil packages are
// kept. The latter is the safe fallback for targets where the running
// kernel could not be determined.
//
// Suppression matches by Pkg.ID, which the dpkg/rpm/apk analyzers populate
// reliably. If a labeled-inactive package has an empty ID — unusual but
// possible for custom analyzers — we cannot suppress its vulns and emit a
// warning so the missed suppression is observable rather than silent.
func suppressInactiveKernelVulns(vulns []types.DetectedVulnerability, pkgs ftypes.Packages) []types.DetectedVulnerability {
	inactive := set.New[string]()
	for _, p := range pkgs {
		if p.Active == nil || *p.Active {
			continue
		}
		if p.ID == "" {
			log.Warn("Inactive kernel package has empty ID; vulnerabilities cannot be suppressed",
				log.String("name", p.Name), log.String("version", p.Version))
			continue
		}
		inactive.Append(p.ID)
	}
	if inactive.Size() == 0 {
		return vulns
	}
	return slices.DeleteFunc(vulns, func(v types.DetectedVulnerability) bool {
		return inactive.Contains(v.PkgID)
	})
}
