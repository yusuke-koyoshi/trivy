package classifier

import (
	"regexp"

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
// Only install-only packages (dnf/yum installonlypkgs: per-kernel copies
// accumulate side by side) are listed. Single-instance siblings from the
// kernel SRPM — kernel-tools*, kernel-headers, kernel-cross-headers,
// kernel-doc, kernel-abi-stablelists/whitelists, kernel-firmware,
// kernel-bootwrapper and their UEK equivalents — never get KernelActive:
// they are upgraded in place, so stale versions never accumulate (nothing
// to suppress), and their content (userspace binaries, firmware blobs)
// stays live no matter which kernel is booted, so an active/inactive
// label keyed on `uname -r` is meaningless and a mismatch — routine when
// they lag the kernel update — would suppress live CVEs.
// kernel-uek-container(-debug) is excluded for the same reason: it boots
// container VMs regardless of the host's running kernel.
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
	"kernel-aarch64",
	"kernel-uki-virt",
	"kernel-debug-uki-virt",
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
	"kernel-uek-core",
	"kernel-uek-devel",
	"kernel-uek-modules",
	"kernel-uek-modules-extra",
	"kernel-uek-modules-internal",
	"kernel-uek-debug",
	"kernel-uek-debug-core",
	"kernel-uek-debug-devel",
	"kernel-uek-debug-modules",
	"kernel-uek-debug-modules-extra",
)

// rpmVersionedKernelPattern matches AL2023's kernel<X.Y>(-<subpkg>)? form
// (e.g. kernel6.12, kernel6.18-modules-extra) introduced when Amazon
// Linux 2023 started shipping multiple kernel majors as parallel package
// families. New majors (kernel7.0, ...) are picked up automatically.
//
// The suffix list mirrors the allow-list criterion above: only
// install-only subpackages whose per-kernel copies accumulate. The kernel
// SRPM's single-instance siblings (kernel6.x-headers, kernel6.x-tools*)
// and userspace siblings (kernel6.x-libbpf*, kernel6.x-debuginfo) are NOT
// included — their content is live regardless of which kernel is booted,
// so labeling them inactive would suppress live CVEs.
//
// AL2023's kernel6.x family does not follow Fedora's modular split, so
// -core / -modules / -modules-core / etc. are not shipped and left out.
var rpmVersionedKernelPattern = regexp.MustCompile(
	`^kernel\d+\.\d+` +
		`(?:-(?:modules-extra|modules-extra-common|devel))?$`,
)

// classifyRPM identifies RHEL-family kernel packages and builds the
// release as `<Version>-<Release>.<Arch>`.
//
// Epoch is excluded: `uname -r` carries no epoch, so the match holds even
// when epoch is bumped (cf. Amazon Linux 2023 kernel epoch=1 transition).
func classifyRPM(pkg types.Package) Result {
	if !rpmKernelPackageNames.Contains(pkg.Name) && !rpmVersionedKernelPattern.MatchString(pkg.Name) {
		return Result{}
	}
	// noarch means arch-independent content built once per SRPM — by
	// construction not an install-only per-kernel payload, so it falls
	// outside KernelActive labeling even if a future allow-list entry or
	// versioned-pattern subpackage ships as noarch.
	if pkg.Arch == "noarch" {
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
