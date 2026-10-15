// Package classifier identifies kernel packages and extracts a release
// string for cross-matching against `uname -r`.
//
// Each distro family has its own naming conventions. Result.Release is
// compared by string equality with `uname -r` (or a kernel banner from
// logs in offline VM scans).
//
// RPM epoch is excluded from Release: `uname -r` exposes no epoch, so the
// match holds even when epoch is bumped (cf. Amazon Linux 2023 kernel
// epoch=1 transition).
package classifier

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Result holds the classifier output.
type Result struct {
	// IsKernel is true when the family-specific rules recognize the package
	// as kernel-related.
	IsKernel bool

	// Release identifies the kernel this package belongs to, comparable
	// against `uname -r`. Empty when IsKernel is false or metadata is
	// insufficient.
	//
	// - Flavor-bound (linux-image-X-cloud-amd64): full uname -r
	//   equivalent, matched by equality.
	// - Flavor-independent (Debian linux-headers-X-common, Ubuntu
	//   version-only linux-headers-X.Y.Z-N): omits the trailing
	//   `-<flavor>`; BaseRelease=true makes the matcher accept any running
	//   kernel beginning with `<Release>-`.
	Release string

	// BaseRelease marks Release as the version base without a flavor
	// suffix, switching the matcher from equality to prefix; see Matches.
	BaseRelease bool
}

// Matches reports whether the running kernel release belongs to this
// package. Flavor-bound packages match by equality; base-release packages
// (BaseRelease=true) match when running begins with `<Release>-`.
func (r Result) Matches(running string) bool {
	if !r.IsKernel || r.Release == "" {
		return false
	}
	if r.BaseRelease {
		return strings.HasPrefix(running, r.Release+"-")
	}
	return r.Release == running
}

// Classify decides whether the package is a kernel package for the distro
// family and returns its release. Returns the zero Result for unsupported
// families and unrecognized packages.
func Classify(pkg types.Package, family types.OSType) Result {
	switch family {
	case types.Debian, types.Ubuntu:
		return classifyDebian(pkg)
	case types.RedHat, types.CentOS, types.CentOSStream, types.Alma, types.Rocky,
		types.Oracle, types.Amazon, types.Fedora:
		return classifyRPM(pkg)
	case types.SLES, types.SLEMicro, types.OpenSUSE, types.OpenSUSELeap, types.OpenSUSETumbleweed:
		return classifySUSE(pkg)
	case types.Alpine:
		return classifyAlpine(pkg)
	default:
		return Result{}
	}
}
