package classifier

import (
	"regexp"
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

// debianVersionOnlyRelease matches the Ubuntu shared-package release shape
// "<version>-<ABI>" (e.g. "5.15.0-92"). The shape must be exact: a looser
// "ends in digits" test would also catch Debian's digit-named flavors
// ("6.1.0-18-686"), turning a flavor-bound package into a prefix matcher
// that cross-matches -686-pae and stops the running -686 kernel from
// matching itself.
var debianVersionOnlyRelease = regexp.MustCompile(`^\d+(?:\.\d+)+-\d+$`)

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
		// Ubuntu shared-headers: no flavor suffix, just "<version>-<ABI>"
		// (e.g. "5.15.0-92"). Running always has a trailing `-<flavor>`,
		// so prefix-match too.
		if debianVersionOnlyRelease.MatchString(release) {
			return Result{IsKernel: true, Release: release, BaseRelease: true}
		}
		// Standard flavor-bound form: release suffix already matches `uname -r`.
		return Result{IsKernel: true, Release: release}
	}
	// "hwe" in the flavor position is the rolling-HWE source-series name,
	// not a boot flavor: its binaries boot as -generic/-lowlatency, so a
	// rebuilt "<release>-hwe" never equals `uname -r`. Treat these shared
	// packages as base-release and prefix-match instead.
	if flavor == "hwe" {
		return Result{IsKernel: true, Release: release, BaseRelease: true}
	}
	// HWE form: rebuild as <release>-<flavor> to match `uname -r`.
	return Result{IsKernel: true, Release: release + "-" + flavor}
}
