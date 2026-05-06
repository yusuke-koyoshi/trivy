// Package classifier identifies kernel packages and extracts the release
// string suitable for cross-matching against `uname -r` output.
//
// Each distro family has its own conventions for naming kernel packages
// and constructing release strings. The Result.Release is intended to be
// compared by string equality with the value of `uname -r` (or a kernel
// banner extracted from logs in offline VM scans).
//
// RPM epoch is intentionally NOT included in Release. `uname -r` does not
// expose epoch, and the comparison must succeed even when epoch is bumped
// (cf. Amazon Linux 2023 kernel epoch=1 transition).
package classifier

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Result holds the classifier output.
type Result struct {
	// IsKernel is true when the input package is a kernel-related package
	// recognized by the family-specific rules.
	IsKernel bool

	// Release identifies the kernel this package belongs to, comparable
	// against `uname -r`. Empty when IsKernel is false, or when the package
	// metadata is insufficient to construct a release string.
	//
	// - For flavor-bound packages (e.g. linux-image-X-cloud-amd64) Release
	//   is the full uname -r equivalent and the matcher uses equality.
	// - For flavor-independent packages (Debian linux-headers-X-common,
	//   Ubuntu version-only linux-headers-X.Y.Z-N) Release omits the
	//   trailing `-<flavor>` segment; BaseRelease=true tells the matcher to
	//   accept any running kernel that begins with `<Release>-`.
	Release string

	// BaseRelease indicates Release is the kernel version base without a
	// flavor suffix. The matcher switches from equality to prefix match
	// when this is true; see Matches.
	BaseRelease bool
}

// Matches reports whether the given running kernel release belongs to this
// classified package. Flavor-bound packages match by exact equality;
// base-release packages (BaseRelease=true) match when running begins with
// `<Release>-`.
func (r Result) Matches(running string) bool {
	if !r.IsKernel || r.Release == "" {
		return false
	}
	if r.BaseRelease {
		return strings.HasPrefix(running, r.Release+"-")
	}
	return r.Release == running
}

// Classify decides whether the given package is a kernel package for the
// distro family and returns its release string.
//
// Returns the zero Result for unsupported families and for packages that
// are not recognized as kernel packages.
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
