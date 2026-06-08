package classifier

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestClassify_Debian(t *testing.T) {
	cases := []struct {
		name   string
		pkg    types.Package
		family types.OSType
		want   Result
	}{
		{
			name:   "linux-image with concrete release",
			pkg:    types.Package{Name: "linux-image-5.15.0-92-generic"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "5.15.0-92-generic"},
		},
		{
			name:   "linux-image-unsigned",
			pkg:    types.Package{Name: "linux-image-unsigned-5.15.0-92-generic"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "5.15.0-92-generic"},
		},
		{
			name:   "linux-headers",
			pkg:    types.Package{Name: "linux-headers-5.15.0-92-generic"},
			family: types.Debian,
			want:   Result{IsKernel: true, Release: "5.15.0-92-generic"},
		},
		{
			name:   "linux-modules-extra",
			pkg:    types.Package{Name: "linux-modules-extra-5.15.0-92-generic"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "5.15.0-92-generic"},
		},
		{
			name:   "linux-modules generic-not-extra",
			pkg:    types.Package{Name: "linux-modules-5.15.0-92-generic"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "5.15.0-92-generic"},
		},
		{
			name:   "AWS flavor binary",
			pkg:    types.Package{Name: "linux-image-5.15.0-1052-aws"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "5.15.0-1052-aws"},
		},
		{
			name:   "Debian amd64 binary",
			pkg:    types.Package{Name: "linux-image-6.1.0-18-amd64"},
			family: types.Debian,
			want:   Result{IsKernel: true, Release: "6.1.0-18-amd64"},
		},
		{
			name:   "meta linux-image-generic excluded",
			pkg:    types.Package{Name: "linux-image-generic"},
			family: types.Ubuntu,
			want:   Result{},
		},
		{
			name:   "meta linux-image-amd64 excluded",
			pkg:    types.Package{Name: "linux-image-amd64"},
			family: types.Debian,
			want:   Result{},
		},
		{
			name:   "meta linux-headers-generic excluded",
			pkg:    types.Package{Name: "linux-headers-generic"},
			family: types.Ubuntu,
			want:   Result{},
		},
		{
			name:   "non-kernel package",
			pkg:    types.Package{Name: "openssl"},
			family: types.Ubuntu,
			want:   Result{},
		},
		// Ubuntu HWE-style packaging: linux-<flavor>-<series>-<type>-<release>.
		// The reconstructed release must match `uname -r` (i.e. release with
		// the flavor appended) so cross-matching against the running kernel
		// works for these packages too.
		{
			name:   "Ubuntu HWE oracle headers",
			pkg:    types.Package{Name: "linux-oracle-6.17-headers-6.17.0-1010"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "6.17.0-1010-oracle"},
		},
		{
			name:   "Ubuntu HWE oracle tools",
			pkg:    types.Package{Name: "linux-oracle-6.17-tools-6.17.0-1011"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "6.17.0-1011-oracle"},
		},
		{
			name:   "Ubuntu HWE aws modules",
			pkg:    types.Package{Name: "linux-aws-5.15-modules-5.15.0-1052"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "5.15.0-1052-aws"},
		},
		{
			name:   "Ubuntu HWE meta with no type-release rejected",
			pkg:    types.Package{Name: "linux-oracle-6.17"},
			family: types.Ubuntu,
			want:   Result{},
		},
		{
			name:   "Ubuntu HWE with non-digit release rejected",
			pkg:    types.Package{Name: "linux-oracle-6.17-headers-something"},
			family: types.Ubuntu,
			want:   Result{},
		},
		// linux-libc-dev is intentionally not classified: it is a libc-side
		// kernel header binary, not a kernel runtime package, and there is
		// only ever one version installed system-wide.
		{
			name:   "linux-libc-dev not a kernel package",
			pkg:    types.Package{Name: "linux-libc-dev"},
			family: types.Ubuntu,
			want:   Result{},
		},
		{
			name:   "linux-base utility scripts not a kernel package",
			pkg:    types.Package{Name: "linux-base"},
			family: types.Ubuntu,
			want:   Result{},
		},
		// Cross-flavor base-release headers: the running kernel reports
		// "<release>-<flavor>" but the base-release headers package carries
		// no flavor (or the literal "-common" suffix), so the matcher must
		// do a prefix comparison rather than equality.
		{
			name:   "Debian base-release headers (literal -common suffix)",
			pkg:    types.Package{Name: "linux-headers-6.12.63+deb13-common"},
			family: types.Debian,
			want:   Result{IsKernel: true, Release: "6.12.63+deb13", BaseRelease: true},
		},
		{
			name:   "Ubuntu base-release headers (no flavor suffix)",
			pkg:    types.Package{Name: "linux-headers-5.15.0-92"},
			family: types.Ubuntu,
			want:   Result{IsKernel: true, Release: "5.15.0-92", BaseRelease: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.pkg, tc.family)
			if got != tc.want {
				t.Errorf("Classify(%q, %s) = %+v; want %+v", tc.pkg.Name, tc.family, got, tc.want)
			}
		})
	}
}

func TestClassify_RPM(t *testing.T) {
	cases := []struct {
		name   string
		pkg    types.Package
		family types.OSType
		want   Result
	}{
		{
			name:   "RHEL kernel basic",
			pkg:    types.Package{Name: "kernel", Version: "5.14.0", Release: "503.el9", Arch: "x86_64"},
			family: types.RedHat,
			want:   Result{IsKernel: true, Release: "5.14.0-503.el9.x86_64"},
		},
		{
			name:   "RHEL kernel-core",
			pkg:    types.Package{Name: "kernel-core", Version: "5.14.0", Release: "503.el9", Arch: "x86_64"},
			family: types.RedHat,
			want:   Result{IsKernel: true, Release: "5.14.0-503.el9.x86_64"},
		},
		{
			name:   "AL2023 kernel epoch=1 (epoch ignored in release)",
			pkg:    types.Package{Name: "kernel", Epoch: 1, Version: "6.1.158", Release: "178.288.amzn2023", Arch: "aarch64"},
			family: types.Amazon,
			want:   Result{IsKernel: true, Release: "6.1.158-178.288.amzn2023.aarch64"},
		},
		{
			name:   "Oracle kernel-uek",
			pkg:    types.Package{Name: "kernel-uek", Version: "5.4.17", Release: "2136.338.4.2.el7uek", Arch: "x86_64"},
			family: types.Oracle,
			want:   Result{IsKernel: true, Release: "5.4.17-2136.338.4.2.el7uek.x86_64"},
		},
		{
			name:   "kernel-debug variant",
			pkg:    types.Package{Name: "kernel-debug", Version: "5.14.0", Release: "503.el9", Arch: "x86_64"},
			family: types.RedHat,
			want:   Result{IsKernel: true, Release: "5.14.0-503.el9.x86_64"},
		},
		{
			name:   "non-kernel rpm package",
			pkg:    types.Package{Name: "glibc", Version: "2.34", Release: "100.el9", Arch: "x86_64"},
			family: types.RedHat,
			want:   Result{},
		},
		{
			name:   "kernel without arch",
			pkg:    types.Package{Name: "kernel", Version: "5.14.0", Release: "503.el9"},
			family: types.RedHat,
			want:   Result{IsKernel: true},
		},
		{
			// Unlisted "kernel-*" packages stay unrecognized, matching the
			// safety stance: under-coverage is OK; over-suppressing CVEs of
			// non-kernel `kernel-*` (livepatch / srpm-macros / rpm-macros)
			// is not.
			name:   "unlisted kernel-* package not classified",
			pkg:    types.Package{Name: "kernel-livepatch-repo-s3", Version: "2023.9.20251117", Release: "0.amzn2023", Arch: "noarch"},
			family: types.Amazon,
			want:   Result{},
		},
		{
			name:   "kernel-srpm-macros not in allow-list",
			pkg:    types.Package{Name: "kernel-srpm-macros", Version: "1.0", Release: "14.amzn2023.0.3", Arch: "noarch"},
			family: types.Amazon,
			want:   Result{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.pkg, tc.family)
			if got != tc.want {
				t.Errorf("Classify(%q, %s) = %+v; want %+v", tc.pkg.Name, tc.family, got, tc.want)
			}
		})
	}
}

func TestClassify_SUSE(t *testing.T) {
	cases := []struct {
		name string
		pkg  types.Package
		want Result
	}{
		{
			name: "SLES kernel-default",
			pkg:  types.Package{Name: "kernel-default", Version: "5.14.21", Release: "150500.55.39.1"},
			want: Result{IsKernel: true, Release: "5.14.21-150500.55.39-default"},
		},
		{
			name: "SLES kernel-azure",
			pkg:  types.Package{Name: "kernel-azure", Version: "5.14.21", Release: "150500.33.42.1"},
			want: Result{IsKernel: true, Release: "5.14.21-150500.33.42-azure"},
		},
		{
			name: "SUSE non-kernel",
			pkg:  types.Package{Name: "kernel-firmware-all", Version: "20240207"},
			want: Result{},
		},
		{
			name: "non-kernel- prefix",
			pkg:  types.Package{Name: "openssl", Version: "1.1"},
			want: Result{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.pkg, types.SLES)
			if got != tc.want {
				t.Errorf("Classify(%q, SLES) = %+v; want %+v", tc.pkg.Name, got, tc.want)
			}
		})
	}
}

func TestClassify_Alpine(t *testing.T) {
	cases := []struct {
		name string
		pkg  types.Package
		want Result
	}{
		{
			name: "linux-virt with apk release",
			pkg:  types.Package{Name: "linux-virt", Version: "5.15.179-r0"},
			want: Result{IsKernel: true, Release: "5.15.179-0-virt"},
		},
		{
			name: "linux-lts",
			pkg:  types.Package{Name: "linux-lts", Version: "6.6.32-r0"},
			want: Result{IsKernel: true, Release: "6.6.32-0-lts"},
		},
		{
			name: "linux-firmware excluded",
			pkg:  types.Package{Name: "linux-firmware", Version: "20240115-r0"},
			want: Result{},
		},
		{
			name: "non-linux package",
			pkg:  types.Package{Name: "musl", Version: "1.2.5-r0"},
			want: Result{},
		},
		{
			// LastIndex of "-r" in upstream-rc + apk-release versions must
			// pick the apk release boundary (-r0), not the upstream rc tag.
			name: "rc kernel uses apk -r boundary",
			pkg:  types.Package{Name: "linux-edge", Version: "5.15.0-rc1-r0"},
			want: Result{IsKernel: true, Release: "5.15.0-rc1-0-edge"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.pkg, types.Alpine)
			if got != tc.want {
				t.Errorf("Classify(%q, Alpine) = %+v; want %+v", tc.pkg.Name, got, tc.want)
			}
		})
	}
}

func TestClassify_UnsupportedFamily(t *testing.T) {
	got := Classify(types.Package{Name: "kernel"}, types.Bottlerocket)
	if got.IsKernel {
		t.Errorf("Classify on Bottlerocket should return zero Result, got %+v", got)
	}
}
