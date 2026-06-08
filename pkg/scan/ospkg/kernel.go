package ospkg

import (
	"slices"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/fanal/kernel/classifier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/types"
)

// labelKernelPackagesWith sets KernelActive=true/false on matching kernel
// packages in place. `running` is passed explicitly so the caller can
// supply it from any source (host syscall, dmesg banner, test fixture).
//
// KernelActive=true goes to kernel packages whose release matches `running`;
// siblings sharing that release (linux-image-X, linux-headers-X) each
// match independently. When entries share an identity
// (Name+Version+Release+Arch) but differ in Epoch — the AL2023
// transition — only the highest-Epoch one stays true. Other kernel
// packages become KernelActive=false. If nothing matches `running`, every
// kernel package is left KernelActive=nil — the safe fallback for extracted
// rootfs / unknown-running-kernel scans.
func labelKernelPackagesWith(pkgs ftypes.Packages, family ftypes.OSType, running string) {
	if running == "" {
		return
	}

	// Detects "same package, different Epoch" — the AL2023 duplicate.
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

	for i, pkg := range pkgs {
		r := classifier.Classify(pkg, family)
		if !r.IsKernel {
			continue
		}
		// No release means we can't prove this kernel is *not* running.
		// Skip it to keep KernelActive=nil and preserve its CVEs; demoting to
		// false could suppress vulns for the real running kernel — a
		// false-negative we explicitly avoid.
		if r.Release == "" {
			continue
		}
		e := entry{
			idx: i,
			key: identityKey{pkg.Name, pkg.Version, pkg.Release, pkg.Arch},
		}
		if r.Matches(running) {
			e.matches = true
			if cur, ok := maxEpochByID[e.key]; !ok || pkg.Epoch > cur {
				maxEpochByID[e.key] = pkg.Epoch
			}
		}
		entries = append(entries, e)
	}

	if len(maxEpochByID) == 0 {
		// Running kernel not in the package set; leave everything KernelActive=nil.
		return
	}

	for _, e := range entries {
		active := e.matches && pkgs[e.idx].Epoch == maxEpochByID[e.key]
		pkgs[e.idx].KernelActive = lo.ToPtr(active)
	}
}

// suppressInactiveKernelVulns drops vulns whose parent package has
// KernelActive=false. KernelActive=true and nil are kept; nil is the safe fallback
// when the running kernel is unknown.
//
// Matches by Pkg.ID, which dpkg/rpm/apk analyzers populate reliably. An
// inactive package with an empty ID — unusual but possible for custom
// analyzers — can't be suppressed, so we warn to keep the miss visible.
func suppressInactiveKernelVulns(vulns []types.DetectedVulnerability, pkgs ftypes.Packages) []types.DetectedVulnerability {
	inactive := set.New[string]()
	for _, p := range pkgs {
		if p.KernelActive == nil || *p.KernelActive {
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
