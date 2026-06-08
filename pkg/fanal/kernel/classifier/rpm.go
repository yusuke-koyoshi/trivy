package classifier

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// rpmKernelPackageNames is the allow-list of RPM kernel binary package
// names across the RHEL family
// (RHEL/CentOS/Alma/Rocky/Oracle/Amazon/Fedora).
//
// An allow-list, not a `kernel-*` prefix match, gives the safer failure
// mode for a security scanner:
//
//   - A missing kernel name leaves its CVEs unsuppressed (noise) until
//     someone notices and adds it.
//   - A prefix match would suppress CVEs on `kernel-*` packages that are
//     NOT kernels (kernel-srpm-macros, kernel-rpm-macros,
//     kernel-livepatch-repo-s3) — a false-negative, the worse direction.
//
// Trade-off: new kernel variants need a manual update. Intentional.
var rpmKernelPackageNames = set.New[string](
	// generic
	"kernel",
	"kernel-core",
	"kernel-modules",
	"kernel-modules-core",
	"kernel-modules-extra",
	"kernel-modules-internal",
	"kernel-modules-partner",
	"kernel-devel",
	"kernel-doc",
	"kernel-firmware",
	"kernel-headers",
	"kernel-tools",
	"kernel-tools-libs",
	"kernel-tools-libs-devel",
	"kernel-aarch64",
	"kernel-bootwrapper",
	"kernel-cross-headers",
	"kernel-uki-virt",
	"kernel-debug-uki-virt",
	"kernel-abi-stablelists",
	"kernel-abi-whitelists",
	// debug
	"kernel-debug",
	"kernel-debug-core",
	"kernel-debug-devel",
	"kernel-debug-modules",
	"kernel-debug-modules-core",
	"kernel-debug-modules-extra",
	"kernel-debug-modules-internal",
	"kernel-debug-modules-partner",
	// 64k page
	"kernel-64k",
	"kernel-64k-core",
	"kernel-64k-devel",
	"kernel-64k-modules",
	"kernel-64k-modules-core",
	"kernel-64k-modules-extra",
	"kernel-64k-debug",
	"kernel-64k-debug-core",
	"kernel-64k-debug-devel",
	"kernel-64k-debug-modules",
	// realtime
	"kernel-rt",
	"kernel-rt-core",
	"kernel-rt-devel",
	"kernel-rt-kvm",
	"kernel-rt-modules",
	"kernel-rt-modules-core",
	"kernel-rt-modules-extra",
	"kernel-rt-modules-internal",
	"kernel-rt-modules-partner",
	"kernel-rt-debug",
	"kernel-rt-debug-core",
	"kernel-rt-debug-devel",
	"kernel-rt-debug-modules",
	"kernel-rt-trace",
	"kernel-rt-trace-devel",
	"kernel-rt-trace-kvm",
	// zfcpdump (s390x)
	"kernel-zfcpdump",
	"kernel-zfcpdump-core",
	"kernel-zfcpdump-devel",
	"kernel-zfcpdump-modules",
	"kernel-zfcpdump-modules-core",
	// xen
	"kernel-xen",
	"kernel-xen-devel",
	// PAE (legacy)
	"kernel-PAE",
	"kernel-PAE-devel",
	// Oracle UEK
	"kernel-uek",
	"kernel-uek-container",
	"kernel-uek-container-debug",
	"kernel-uek-core",
	"kernel-uek-devel",
	"kernel-uek-doc",
	"kernel-uek-firmware",
	"kernel-uek-headers",
	"kernel-uek-modules",
	"kernel-uek-modules-extra",
	"kernel-uek-modules-internal",
	"kernel-uek-tools",
	"kernel-uek-tools-libs",
	"kernel-uek-tools-libs-devel",
	"kernel-uek-debug",
	"kernel-uek-debug-core",
	"kernel-uek-debug-devel",
	"kernel-uek-debug-modules",
	"kernel-uek-debug-modules-extra",
)

// classifyRPM identifies RHEL-family kernel packages and builds the
// release as `<Version>-<Release>.<Arch>`.
//
// Epoch is excluded: `uname -r` carries no epoch, so the match holds even
// when epoch is bumped (cf. Amazon Linux 2023 kernel epoch=1 transition).
func classifyRPM(pkg types.Package) Result {
	if !rpmKernelPackageNames.Contains(pkg.Name) {
		return Result{}
	}
	if pkg.Version == "" || pkg.Release == "" || pkg.Arch == "" {
		// Kernel, but no comparable release can be built.
		return Result{IsKernel: true}
	}
	return Result{
		IsKernel: true,
		Release:  pkg.Version + "-" + pkg.Release + "." + pkg.Arch,
	}
}
