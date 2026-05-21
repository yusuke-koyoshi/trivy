package classifier

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// debianKernelPackagePattern recognizes Debian/Ubuntu kernel binary
// packages in two naming forms and reconstructs the `uname -r`-equivalent
// release string.
//
//  1. Standard form: linux-<type>-<release>
//     e.g. linux-image-5.15.0-92-generic   → release: 5.15.0-92-generic
//
//  2. HWE (Hardware Enablement) form: linux-<flavor>-<series>-<type>-<release>
//     e.g. linux-oracle-6.17-headers-6.17.0-1010
//     → flavor=oracle, series=6.17, type=headers, release=6.17.0-1010
//     → reconstructed `uname -r` form: 6.17.0-1010-oracle
//
// The HWE form arose from Ubuntu's cloud kernel packaging where a flavor
// (oracle/aws/gcp/...) and series (6.17 etc.) are nested between "linux-"
// and the package type. Without recognizing this form, kernel CVEs that
// Ubuntu Security Tracker attaches to these binaries (e.g.
// `linux-oracle-6.17-headers-X.Y.Z-N`) are not subject to the inactive-
// kernel suppression in pkg/scan/ospkg.
//
// The release segment must start with a digit. Names like
// `linux-image-generic` (meta package) and `linux-libc-dev` (libc-side
// kernel headers, not a kernel binary) are rejected because their suffix
// is non-numeric. The type alternation lists longer variants first
// (`modules-extra` before `modules`) so the leftmost-longest match picks
// the correct package type.
var debianKernelPackagePattern = regexp.MustCompile(
	`^linux(?:-(?P<flavor>[a-z][a-z0-9]*)-(?P<series>\d+\.\d+))?-` +
		`(?P<type>image-unsigned|signed-image|image-uc|image|` +
		`modules-extra|modules|headers|cloud-tools|tools|buildinfo|lib-rust)` +
		`-(?P<release>\d.+)$`,
)

var (
	debianFlavorIndex  = debianKernelPackagePattern.SubexpIndex("flavor")
	debianReleaseIndex = debianKernelPackagePattern.SubexpIndex("release")
)

func classifyDebian(pkg types.Package) Result {
	// Cheap prefix gate to skip the regex engine for the vast majority of
	// dpkg packages whose names cannot match (e.g. libc6, bash, python3-*).
	// Aligns with the prefix-gate pattern in classifyAlpine / classifySUSE.
	if !strings.HasPrefix(pkg.Name, "linux-") {
		return Result{}
	}
	m := debianKernelPackagePattern.FindStringSubmatch(pkg.Name)
	if m == nil {
		return Result{}
	}
	release := m[debianReleaseIndex]
	flavor := m[debianFlavorIndex]
	if flavor == "" {
		// Debian shared-headers convention: literal "-common" trailer marks
		// the cross-flavor package. Strip it so the prefix match against
		// running (e.g. "6.12.63+deb13-cloud-amd64") succeeds.
		if strings.HasSuffix(release, "-common") {
			return Result{
				IsKernel:    true,
				Release:     strings.TrimSuffix(release, "-common"),
				BaseRelease: true,
			}
		}
		// Ubuntu shared-headers convention: no flavor suffix, release ends
		// with the build number (e.g. "5.15.0-92"). The running kernel
		// always has a trailing `-<flavor>` so this is also a prefix match.
		if i := strings.LastIndex(release, "-"); i >= 0 {
			if _, err := strconv.Atoi(release[i+1:]); err == nil {
				return Result{IsKernel: true, Release: release, BaseRelease: true}
			}
		}
		// Standard flavor-bound form: release suffix already matches `uname -r`.
		return Result{IsKernel: true, Release: release}
	}
	// HWE form: rebuild as <release>-<flavor> so the comparison key matches
	// the value the kernel reports via `uname -r`.
	return Result{IsKernel: true, Release: release + "-" + flavor}
}
