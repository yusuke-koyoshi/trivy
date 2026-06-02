package classifier

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// debianKernelPackagePattern recognizes Debian/Ubuntu kernel binary
// packages in two naming forms and rebuilds the `uname -r` release:
//
//  1. Standard linux-<type>-<release>:
//     linux-image-5.15.0-92-generic → 5.15.0-92-generic
//  2. HWE linux-<flavor>-<series>-<type>-<release>:
//     linux-oracle-6.17-headers-6.17.0-1010 → 6.17.0-1010-oracle
//
// The HWE form is Ubuntu cloud-kernel packaging, nesting a flavor
// (oracle/aws/gcp/...) and series between "linux-" and the type. Without
// it, CVEs Ubuntu attaches to these binaries escape inactive-kernel
// suppression in pkg/scan/ospkg.
//
// The release segment must start with a digit, so meta/non-binary names
// (linux-image-generic, linux-libc-dev) are rejected. The type
// alternation lists longer variants first (modules-extra before modules)
// for correct leftmost-longest match.
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
	// Prefix gate skips the regex for the many dpkg names that can't match
	// (libc6, bash, python3-*). Mirrors classifyAlpine/classifySUSE.
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
		// Debian shared-headers: "-common" trailer marks the cross-flavor
		// package. Strip it so the prefix match against running (e.g.
		// "6.12.63+deb13-cloud-amd64") works.
		if rel, ok := strings.CutSuffix(release, "-common"); ok {
			return Result{
				IsKernel:    true,
				Release:     rel,
				BaseRelease: true,
			}
		}
		// Ubuntu shared-headers: no flavor suffix, release ends with the
		// build number (e.g. "5.15.0-92"). Running always has a trailing
		// `-<flavor>`, so prefix-match too.
		if i := strings.LastIndex(release, "-"); i >= 0 {
			if _, err := strconv.Atoi(release[i+1:]); err == nil {
				return Result{IsKernel: true, Release: release, BaseRelease: true}
			}
		}
		// Standard flavor-bound form: release suffix already matches `uname -r`.
		return Result{IsKernel: true, Release: release}
	}
	// HWE form: rebuild as <release>-<flavor> to match `uname -r`.
	return Result{IsKernel: true, Release: release + "-" + flavor}
}
