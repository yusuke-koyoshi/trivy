package ospkg

import (
	"testing"

	"github.com/samber/lo"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestLabelKernelPackagesWith_DebianMatchAndMismatch(t *testing.T) {
	pkgs := ftypes.Packages{
		{ID: "openssl", Name: "openssl"},
		{ID: "linux-image-old", Name: "linux-image-5.15.0-89-generic"},
		{ID: "linux-image-new", Name: "linux-image-5.15.0-92-generic"},
		{ID: "linux-headers-new", Name: "linux-headers-5.15.0-92-generic"},
	}
	labelKernelPackagesWith(pkgs, ftypes.Ubuntu, "5.15.0-92-generic")

	if pkgs[0].Active != nil {
		t.Errorf("openssl Active = %v; want nil", pkgs[0].Active)
	}
	if pkgs[1].Active == nil || *pkgs[1].Active {
		t.Errorf("linux-image-old Active = %v; want false", pkgs[1].Active)
	}
	if pkgs[2].Active == nil || !*pkgs[2].Active {
		t.Errorf("linux-image-new Active = %v; want true", pkgs[2].Active)
	}
	if pkgs[3].Active == nil || !*pkgs[3].Active {
		t.Errorf("linux-headers-new Active = %v; want true (matches running release)", pkgs[3].Active)
	}
}

// TestLabelKernelPackagesWith_DebianCommonHeaders covers the cross-flavor
// "common" headers convention. The running kernel reports a flavor-suffixed
// release such as "6.12.63+deb13-cloud-amd64", while the shared headers
// package is named "linux-headers-6.12.63+deb13-common" with no flavor.
// Without prefix matching the common package would be demoted to
// Active=false even though it belongs to the running kernel.
func TestLabelKernelPackagesWith_DebianCommonHeaders(t *testing.T) {
	pkgs := ftypes.Packages{
		{ID: "linux-image-running", Name: "linux-image-6.12.63+deb13-cloud-amd64"},
		{ID: "linux-headers-running", Name: "linux-headers-6.12.63+deb13-cloud-amd64"},
		{ID: "linux-headers-common-running", Name: "linux-headers-6.12.63+deb13-common"},
		{ID: "linux-headers-common-other", Name: "linux-headers-6.12.73+deb13-common"},
	}
	labelKernelPackagesWith(pkgs, ftypes.Debian, "6.12.63+deb13-cloud-amd64")

	if pkgs[0].Active == nil || !*pkgs[0].Active {
		t.Errorf("flavor-bound running image: want Active=true; got %v", pkgs[0].Active)
	}
	if pkgs[1].Active == nil || !*pkgs[1].Active {
		t.Errorf("flavor-bound running headers: want Active=true; got %v", pkgs[1].Active)
	}
	if pkgs[2].Active == nil || !*pkgs[2].Active {
		t.Errorf("common headers matching running version: want Active=true; got %v", pkgs[2].Active)
	}
	if pkgs[3].Active == nil || *pkgs[3].Active {
		t.Errorf("common headers for unrelated version: want Active=false; got %v", pkgs[3].Active)
	}
}

// TestLabelKernelPackagesWith_UbuntuVersionOnlyHeaders mirrors the Debian
// case for Ubuntu's "no flavor suffix" headers package convention.
func TestLabelKernelPackagesWith_UbuntuVersionOnlyHeaders(t *testing.T) {
	pkgs := ftypes.Packages{
		{ID: "linux-image-running", Name: "linux-image-5.15.0-92-generic"},
		{ID: "linux-headers-version-running", Name: "linux-headers-5.15.0-92"},
		{ID: "linux-headers-version-other", Name: "linux-headers-5.15.0-89"},
	}
	labelKernelPackagesWith(pkgs, ftypes.Ubuntu, "5.15.0-92-generic")

	if pkgs[0].Active == nil || !*pkgs[0].Active {
		t.Errorf("flavor-bound running image: want Active=true; got %v", pkgs[0].Active)
	}
	if pkgs[1].Active == nil || !*pkgs[1].Active {
		t.Errorf("version-only headers matching running: want Active=true; got %v", pkgs[1].Active)
	}
	if pkgs[2].Active == nil || *pkgs[2].Active {
		t.Errorf("version-only headers for older kernel: want Active=false; got %v", pkgs[2].Active)
	}
}

func TestLabelKernelPackagesWith_NoMatchFallback(t *testing.T) {
	// A Debian rootfs scanned from a host whose uname -r differs.
	pkgs := ftypes.Packages{
		{ID: "linux-image-debian", Name: "linux-image-6.1.0-18-amd64"},
		{ID: "linux-headers-debian", Name: "linux-headers-6.1.0-18-amd64"},
	}
	labelKernelPackagesWith(pkgs, ftypes.Debian, "5.14.0-503.el9.x86_64") // RHEL host kernel

	for i := range pkgs {
		if pkgs[i].Active != nil {
			t.Errorf("pkg[%d] Active = %v; want nil (fallback)", i, pkgs[i].Active)
		}
	}
}

func TestLabelKernelPackagesWith_AL2023EpochTransition(t *testing.T) {
	// AL2023 transition: epoch=0 and epoch=1 of the same kernel V-R both installed.
	pkgs := ftypes.Packages{
		{ID: "kernel-epoch0", Name: "kernel", Epoch: 0, Version: "6.1.158", Release: "178.288.amzn2023", Arch: "aarch64"},
		{ID: "kernel-epoch1", Name: "kernel", Epoch: 1, Version: "6.1.158", Release: "178.288.amzn2023", Arch: "aarch64"},
	}
	labelKernelPackagesWith(pkgs, ftypes.Amazon, "6.1.158-178.288.amzn2023.aarch64")

	if pkgs[0].Active == nil || *pkgs[0].Active {
		t.Errorf("epoch=0 should be Active=false; got %v", pkgs[0].Active)
	}
	if pkgs[1].Active == nil || !*pkgs[1].Active {
		t.Errorf("epoch=1 should be Active=true; got %v", pkgs[1].Active)
	}
}

func TestLabelKernelPackagesWith_EmptyRunning(t *testing.T) {
	pkgs := ftypes.Packages{
		{ID: "linux-image", Name: "linux-image-5.15.0-92-generic"},
	}
	labelKernelPackagesWith(pkgs, ftypes.Ubuntu, "")
	if pkgs[0].Active != nil {
		t.Errorf("empty running should leave Active=nil; got %v", pkgs[0].Active)
	}
}

// TestLabelKernelPackagesWith_KernelWithoutReleaseStaysNil verifies that a
// kernel package the classifier could not produce a release string for is
// left Active=nil even when other kernels match the running release. The
// alternative (Active=false) would silently suppress its vulns even when
// the package might actually be the running kernel.
func TestLabelKernelPackagesWith_KernelWithoutReleaseStaysNil(t *testing.T) {
	pkgs := ftypes.Packages{
		// A kernel-default with single-segment Release: classifier returns
		// IsKernel=true but Release="" because trimming would be unsafe.
		{ID: "kernel-default-noseg", Name: "kernel-default", Version: "5.14.21", Release: "150500"},
		// Another SUSE kernel that does match the running release. Without
		// the fix, the noseg one above would be demoted to Active=false.
		{ID: "kernel-default-match", Name: "kernel-default", Version: "5.14.21", Release: "150500.55.39.1"},
	}
	labelKernelPackagesWith(pkgs, ftypes.SLES, "5.14.21-150500.55.39-default")

	if pkgs[0].Active != nil {
		t.Errorf("kernel without release should stay Active=nil; got %v", pkgs[0].Active)
	}
	if pkgs[1].Active == nil || !*pkgs[1].Active {
		t.Errorf("matching kernel should be Active=true; got %v", pkgs[1].Active)
	}
}

// TestHasKernelPackage covers the early-return gate that prevents
// labelKernelPackages from reading /proc when the target has no kernel
// packages at all. This skips the cachedRunning() call for container image
// scans that lack a kernel binary (the common case) and OS-package-empty
// targets such as repository scans and partial rootfs without a package DB.
func TestHasKernelPackage(t *testing.T) {
	cases := []struct {
		name   string
		pkgs   ftypes.Packages
		family ftypes.OSType
		want   bool
	}{
		{
			name: "linux-image present",
			pkgs: ftypes.Packages{
				{Name: "openssl"},
				{Name: "linux-image-5.15.0-92-generic"},
			},
			family: ftypes.Ubuntu,
			want:   true,
		},
		{
			name: "kernel-uek present (oracle)",
			pkgs: ftypes.Packages{
				{Name: "kernel-uek", Version: "5.15.0", Release: "306.el8uek", Arch: "x86_64"},
			},
			family: ftypes.Oracle,
			want:   true,
		},
		{
			name: "no kernel packages (container image typical case)",
			pkgs: ftypes.Packages{
				{Name: "openssl"},
				{Name: "bash"},
				{Name: "libc6"},
			},
			family: ftypes.Ubuntu,
			want:   false,
		},
		{
			name:   "empty packages",
			pkgs:   ftypes.Packages{},
			family: ftypes.Ubuntu,
			want:   false,
		},
		{
			name: "Debian meta-package excluded as non-kernel",
			pkgs: ftypes.Packages{
				{Name: "linux-image-generic"},
				{Name: "linux-libc-dev"},
			},
			family: ftypes.Ubuntu,
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasKernelPackage(tc.pkgs, tc.family); got != tc.want {
				t.Errorf("hasKernelPackage = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestSuppressInactiveKernelVulns_RealisticPkgIDFormat(t *testing.T) {
	// Mirror the dpkg/rpm analyzer ID format ("Name@Version[-Release[.Arch]]")
	// to lock in that suppression works end-to-end with real PkgIDs.
	tru := true
	fls := false
	pkgs := ftypes.Packages{
		{
			ID: "linux-image-5.15.0-89-generic@5.15.0-89.99",
			Name: "linux-image-5.15.0-89-generic", Version: "5.15.0-89.99",
			Active: &fls,
		},
		{
			ID: "linux-image-5.15.0-92-generic@5.15.0-92.102",
			Name: "linux-image-5.15.0-92-generic", Version: "5.15.0-92.102",
			Active: &tru,
		},
	}
	vulns := []types.DetectedVulnerability{
		{VulnerabilityID: "CVE-OLD", PkgID: "linux-image-5.15.0-89-generic@5.15.0-89.99"},
		{VulnerabilityID: "CVE-NEW", PkgID: "linux-image-5.15.0-92-generic@5.15.0-92.102"},
	}
	got := suppressInactiveKernelVulns(vulns, pkgs)
	if len(got) != 1 || got[0].VulnerabilityID != "CVE-NEW" {
		t.Errorf("expected only CVE-NEW to survive; got %+v", got)
	}
}

func TestSuppressInactiveKernelVulns(t *testing.T) {
	tru := true
	fls := false

	pkgs := ftypes.Packages{
		{ID: "linux-image-active", Name: "linux-image-5.15.0-92-generic", Active: &tru},
		{ID: "linux-image-old", Name: "linux-image-5.15.0-89-generic", Active: &fls},
		{ID: "openssl", Name: "openssl"}, // Active=nil
	}

	vulns := []types.DetectedVulnerability{
		{VulnerabilityID: "CVE-A", PkgID: "linux-image-active", PkgName: "linux-image-5.15.0-92-generic"},
		{VulnerabilityID: "CVE-B", PkgID: "linux-image-old", PkgName: "linux-image-5.15.0-89-generic"},
		{VulnerabilityID: "CVE-C", PkgID: "linux-image-old", PkgName: "linux-image-5.15.0-89-generic"},
		{VulnerabilityID: "CVE-D", PkgID: "openssl", PkgName: "openssl"},
	}

	got := suppressInactiveKernelVulns(vulns, pkgs)

	wantIDs := []string{"CVE-A", "CVE-D"}
	if len(got) != len(wantIDs) {
		t.Fatalf("got %d vulns, want %d (%+v)", len(got), len(wantIDs), got)
	}
	for i, v := range got {
		if v.VulnerabilityID != wantIDs[i] {
			t.Errorf("vuln[%d] = %s; want %s", i, v.VulnerabilityID, wantIDs[i])
		}
	}
}

func TestSuppressInactiveKernelVulns_NoInactive(t *testing.T) {
	tru := true
	pkgs := ftypes.Packages{
		{ID: "linux-image-active", Name: "linux-image-5.15.0-92-generic", Active: &tru},
		{ID: "openssl", Name: "openssl"},
	}
	vulns := []types.DetectedVulnerability{
		{VulnerabilityID: "CVE-A", PkgID: "linux-image-active"},
		{VulnerabilityID: "CVE-B", PkgID: "openssl"},
	}
	got := suppressInactiveKernelVulns(vulns, pkgs)
	if len(got) != 2 {
		t.Errorf("expected no suppression, got %d vulns (want 2)", len(got))
	}
}

// TestLabelAndSuppress_Integration exercises the labeling + suppression
// pipeline together, mirroring the order in scan.go (label first, then
// detect, then suppress). It feeds in fixture packages and a synthesized
// vuln list, then asserts both the SBOM-side labels and the surviving
// vulnerabilities.
func TestLabelAndSuppress_Integration(t *testing.T) {
	cases := []struct {
		name              string
		family            ftypes.OSType
		running           string
		pkgs              ftypes.Packages
		vulns             []types.DetectedVulnerability
		wantActiveByID    map[string]*bool // nil pointer means we expect Active=nil
		wantSurvivingVuln []string
	}{
		{
			name:    "ubuntu old and new kernel",
			family:  ftypes.Ubuntu,
			running: "5.15.0-92-generic",
			pkgs: ftypes.Packages{
				{ID: "linux-image-old@old", Name: "linux-image-5.15.0-89-generic"},
				{ID: "linux-image-new@new", Name: "linux-image-5.15.0-92-generic"},
				{ID: "linux-headers-new@new", Name: "linux-headers-5.15.0-92-generic"},
				{ID: "openssl@1", Name: "openssl"},
			},
			vulns: []types.DetectedVulnerability{
				{VulnerabilityID: "CVE-OLD-1", PkgID: "linux-image-old@old"},
				{VulnerabilityID: "CVE-NEW-1", PkgID: "linux-image-new@new"},
				{VulnerabilityID: "CVE-NEW-2", PkgID: "linux-headers-new@new"},
				{VulnerabilityID: "CVE-SSL-1", PkgID: "openssl@1"},
			},
			wantActiveByID: map[string]*bool{
				"linux-image-old@old":   lo.ToPtr(false),
				"linux-image-new@new":   lo.ToPtr(true),
				"linux-headers-new@new": lo.ToPtr(true),
				"openssl@1":             nil,
			},
			wantSurvivingVuln: []string{"CVE-NEW-1", "CVE-NEW-2", "CVE-SSL-1"},
		},
		{
			name:    "AL2023 epoch=0 + epoch=1 transition (epoch=1 is active)",
			family:  ftypes.Amazon,
			running: "6.1.158-178.288.amzn2023.aarch64",
			pkgs: ftypes.Packages{
				{ID: "kernel@e0", Name: "kernel", Epoch: 0, Version: "6.1.158", Release: "178.288.amzn2023", Arch: "aarch64"},
				{ID: "kernel@e1", Name: "kernel", Epoch: 1, Version: "6.1.158", Release: "178.288.amzn2023", Arch: "aarch64"},
			},
			vulns: []types.DetectedVulnerability{
				{VulnerabilityID: "CVE-EPOCH-0", PkgID: "kernel@e0"},
				{VulnerabilityID: "CVE-EPOCH-1", PkgID: "kernel@e1"},
			},
			wantActiveByID: map[string]*bool{
				"kernel@e0": lo.ToPtr(false),
				"kernel@e1": lo.ToPtr(true),
			},
			wantSurvivingVuln: []string{"CVE-EPOCH-1"},
		},
		{
			name:    "running kernel unknown to target (extracted rootfs)",
			family:  ftypes.Debian,
			running: "5.14.0-503.el9.x86_64", // RHEL host kernel; target is Debian
			pkgs: ftypes.Packages{
				{ID: "linux-image-deb@1", Name: "linux-image-6.1.0-18-amd64"},
				{ID: "linux-image-deb@2", Name: "linux-image-6.1.0-19-amd64"},
			},
			vulns: []types.DetectedVulnerability{
				{VulnerabilityID: "CVE-DEB-1", PkgID: "linux-image-deb@1"},
				{VulnerabilityID: "CVE-DEB-2", PkgID: "linux-image-deb@2"},
			},
			wantActiveByID: map[string]*bool{
				"linux-image-deb@1": nil,
				"linux-image-deb@2": nil,
			},
			wantSurvivingVuln: []string{"CVE-DEB-1", "CVE-DEB-2"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			labelKernelPackagesWith(tc.pkgs, tc.family, tc.running)

			for _, p := range tc.pkgs {
				want, ok := tc.wantActiveByID[p.ID]
				if !ok {
					t.Errorf("unexpected package %q in result", p.ID)
					continue
				}
				switch {
				case want == nil && p.Active != nil:
					t.Errorf("pkg %q Active = %v; want nil", p.ID, *p.Active)
				case want != nil && p.Active == nil:
					t.Errorf("pkg %q Active = nil; want %v", p.ID, *want)
				case want != nil && p.Active != nil && *want != *p.Active:
					t.Errorf("pkg %q Active = %v; want %v", p.ID, *p.Active, *want)
				}
			}

			got := suppressInactiveKernelVulns(tc.vulns, tc.pkgs)
			gotIDs := make([]string, 0, len(got))
			for _, v := range got {
				gotIDs = append(gotIDs, v.VulnerabilityID)
			}
			if len(gotIDs) != len(tc.wantSurvivingVuln) {
				t.Fatalf("surviving vulns = %v; want %v", gotIDs, tc.wantSurvivingVuln)
			}
			for i, id := range gotIDs {
				if id != tc.wantSurvivingVuln[i] {
					t.Errorf("surviving[%d] = %s; want %s", i, id, tc.wantSurvivingVuln[i])
				}
			}
		})
	}
}

func TestSuppressInactiveKernelVulns_AllNil(t *testing.T) {
	pkgs := ftypes.Packages{
		{ID: "linux-image-a", Name: "linux-image-X"},
		{ID: "linux-image-b", Name: "linux-image-Y"},
	}
	vulns := []types.DetectedVulnerability{
		{VulnerabilityID: "CVE-A", PkgID: "linux-image-a"},
		{VulnerabilityID: "CVE-B", PkgID: "linux-image-b"},
	}
	got := suppressInactiveKernelVulns(vulns, pkgs)
	if len(got) != 2 {
		t.Errorf("Active=nil should not suppress; got %d vulns (want 2)", len(got))
	}
}
