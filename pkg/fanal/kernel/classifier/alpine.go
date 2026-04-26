package classifier

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// alpineKernelFlavors lists Alpine kernel package flavor suffixes.
// The Alpine kernel binary package is named `linux-<flavor>`.
//
// Note: `linux-firmware` is intentionally excluded; it is firmware and not a
// kernel package. Membership in this set is the only kernel gate.
var alpineKernelFlavors = set.New[string](
	"lts",
	"virt",
	"edge",
	"rpi",
	"rpi4",
	"rpi-armv7",
	"rpi-aarch64",
)

// classifyAlpine recognizes Alpine kernel packages and constructs a release
// string compatible with `uname -r`.
//
// Alpine apk packages store the full version (including apk release suffix
// like "-r0") in Pkg.Version. `uname -r` on Alpine looks like
// "5.15.179-0-virt" (apk "-r0" becomes "-0-<flavor>"), so we strip the "-r"
// prefix from the apk release component and append the flavor.
//
// This implementation is best-effort. Custom kernel packages built outside
// of apk's standard naming conventions are not recognized.
func classifyAlpine(pkg types.Package) Result {
	flavor := strings.TrimPrefix(pkg.Name, "linux-")
	if flavor == pkg.Name {
		return Result{}
	}
	if !alpineKernelFlavors.Contains(flavor) {
		return Result{}
	}
	if pkg.Version == "" {
		return Result{IsKernel: true}
	}
	// Convert apk version "5.15.179-r0" -> uname-style "5.15.179-0".
	// Use the rightmost "-r<digits>" to avoid matching upstream tags such
	// as "-rc1" that may also appear earlier in the version.
	idx := strings.LastIndex(pkg.Version, "-r")
	if idx < 0 {
		return Result{IsKernel: true}
	}
	releaseNum := pkg.Version[idx+len("-r"):]
	if _, err := strconv.Atoi(releaseNum); err != nil {
		return Result{IsKernel: true}
	}
	base := pkg.Version[:idx]
	return Result{
		IsKernel: true,
		Release:  base + "-" + releaseNum + "-" + flavor,
	}
}
