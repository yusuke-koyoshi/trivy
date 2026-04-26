package classifier

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// suseKernelFlavors lists kernel flavor suffixes recognized on SUSE-family
// distros (SLES, SLE Micro, openSUSE Leap/Tumbleweed). The flavor appears
// both as the package-name suffix (`kernel-<flavor>`) and as the suffix of
// `uname -r`.
var suseKernelFlavors = set.New[string](
	"default",
	"default-base",
	"azure",
	"rt",
	"rt_debug",
	"vanilla",
	"xen",
	"debug",
	"kvmsmall",
)

// classifySUSE constructs the release string in the form
// `<Version>-<Release-trimmed>-<flavor>` where Release-trimmed drops the
// last `.NN` segment of Pkg.Release because `uname -r` does not show it.
//
// Example: kernel-default 5.14.21-150500.55.39.1 on the SLES 15 kernel
// produces "5.14.21-150500.55.39-default", matching `uname -r`.
func classifySUSE(pkg types.Package) Result {
	flavor := strings.TrimPrefix(pkg.Name, "kernel-")
	if flavor == pkg.Name {
		return Result{}
	}
	if !suseKernelFlavors.Contains(flavor) {
		return Result{}
	}
	if pkg.Version == "" || pkg.Release == "" {
		return Result{IsKernel: true}
	}
	// SUSE convention: Release always carries at least one `.NN` segment that
	// `uname -r` does not show (e.g. "150500.55.39.1" -> trim ".1"). A
	// single-segment Release (no dots) cannot be safely trimmed; recognize
	// the package as a kernel but emit no Release rather than guess.
	parts := strings.Split(pkg.Release, ".")
	if len(parts) < 2 {
		return Result{IsKernel: true}
	}
	trimmed := strings.Join(parts[:len(parts)-1], ".")
	return Result{
		IsKernel: true,
		Release:  pkg.Version + "-" + trimmed + "-" + flavor,
	}
}
