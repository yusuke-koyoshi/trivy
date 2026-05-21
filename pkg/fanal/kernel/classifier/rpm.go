package classifier

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// rpmKernelPackageNames is the explicit allow-list of RPM binary package
// names recognized as kernel-related across the RHEL family
// (RHEL/CentOS/Alma/Rocky/Oracle/Amazon/Fedora).
//
// We use an allow-list rather than a structural `kernel-*` prefix match.
// Compared with prefix matching, an allow-list has a safer failure mode
// for a security scanner:
//
//   - A new kernel-related package missing from the list silently leaves
//     its CVEs unsuppressed (under-coverage / noise). Someone notices it
//     and fixes the list.
//   - A prefix match would instead silently suppress CVEs published
//     against `kernel-*` packages that are NOT kernels (e.g.
//     `kernel-livepatch-repo-s3`, `kernel-srpm-macros`,
//     `kernel-rpm-macros`). That is a false-negative — a worse failure
//     direction.
//
// Trade-off: when distros add new kernel variants (e.g.
// `kernel-uek-container` from Oracle, AL2023's kernel6.12 family), this
// list must be updated by hand. The maintenance burden is intentional.
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

// classifyRPM identifies kernel packages on RHEL-family distros and
// constructs the release string in the form `<Version>-<Release>.<Arch>`.
//
// Pkg.Epoch is intentionally NOT included; `uname -r` never carries an
// epoch prefix, so omitting it keeps the cross-match correct even when
// epoch is bumped (cf. Amazon Linux 2023 kernel epoch=1 transition).
//
// We use Pkg.Epoch (binary), not Pkg.SrcEpoch. For kernel packages they
// are normally identical, and the running kernel is what matters for
// cross-matching against `uname -r`.
func classifyRPM(pkg types.Package) Result {
	if !rpmKernelPackageNames.Contains(pkg.Name) {
		return Result{}
	}
	if pkg.Version == "" || pkg.Release == "" || pkg.Arch == "" {
		// Recognized as kernel but cannot construct a comparable release.
		return Result{IsKernel: true}
	}
	return Result{
		IsKernel: true,
		Release:  pkg.Version + "-" + pkg.Release + "." + pkg.Arch,
	}
}
