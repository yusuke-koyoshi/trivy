package io_test

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
)

func rpmKernel(id, version string, active *bool) ftypes.Package {
	return ftypes.Package{
		ID:           id,
		Name:         "kernel",
		Version:      version,
		Arch:         "x86_64",
		KernelActive: active,
		Identifier: ftypes.PkgIdentifier{
			UID: id,
			PURL: &packageurl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "kernel",
				Version:   version,
			},
		},
	}
}

// TestKernelActive_RoundTrip checks Package.KernelActive survives an
// encode→decode cycle. A nil flag must emit no property (so it decodes back
// to nil rather than false), which is what distinguishes "not the running
// kernel" from "not a kernel package / unknown".
func TestKernelActive_RoundTrip(t *testing.T) {
	report := types.Report{
		SchemaVersion: 2,
		ArtifactName:  "rhel",
		ArtifactType:  ftypes.TypeContainerImage,
		Metadata:      types.Metadata{OS: &ftypes.OS{Family: ftypes.RedHat, Name: "9"}},
		Results: []types.Result{
			{
				Target: "rhel",
				Type:   ftypes.RedHat,
				Class:  types.ClassOSPkg,
				Packages: []ftypes.Package{
					rpmKernel("kernel-running", "5.14.0-running.el9", lo.ToPtr(true)),
					rpmKernel("kernel-old", "5.14.0-old.el9", lo.ToPtr(false)),
					{
						ID:      "bash",
						Name:    "bash",
						Version: "5.1.8",
						Arch:    "x86_64",
						Identifier: ftypes.PkgIdentifier{
							UID:  "bash",
							PURL: &packageurl.PackageURL{Type: packageurl.TypeRPM, Namespace: "redhat", Name: "bash", Version: "5.1.8"},
						},
					},
				},
			},
		},
	}

	bom, err := sbomio.NewEncoder(sbomio.WithBOMRef()).Encode(report)
	require.NoError(t, err)

	var sbom types.SBOM
	require.NoError(t, sbomio.NewDecoder(bom).Decode(t.Context(), &sbom))

	got := make(map[string]*bool)
	for _, pi := range sbom.Packages {
		for _, p := range pi.Packages {
			got[p.ID] = p.KernelActive
		}
	}
	assert.Equal(t, lo.ToPtr(true), got["kernel-running"])
	assert.Equal(t, lo.ToPtr(false), got["kernel-old"])
	assert.Nil(t, got["bash"], "non-kernel package must stay KernelActive=nil")
}
