package artifact

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Test_disabledAnalyzers(t *testing.T) {
	tests := []struct {
		name           string
		opts           flag.Options
		expectDisabled bool // whether TypeJar should be in the disabled list
	}{
		{
			name: "scanners=none, pkg-types=os,library: TypeJar should NOT be disabled",
			opts: flag.Options{
				PackageOptions: flag.PackageOptions{
					PkgTypes: []string{types.PkgTypeOS, types.PkgTypeLibrary},
				},
				ScanOptions: flag.ScanOptions{
					Scanners: nil,
				},
			},
			expectDisabled: false,
		},
		{
			name: "scanners=none, pkg-types=os: TypeJar should be disabled via TypeLanguages",
			opts: flag.Options{
				PackageOptions: flag.PackageOptions{
					PkgTypes: []string{types.PkgTypeOS},
				},
				ScanOptions: flag.ScanOptions{
					Scanners: nil,
				},
			},
			expectDisabled: true,
		},
		{
			name: "scanners=vuln, pkg-types=os,library: TypeJar should NOT be disabled",
			opts: flag.Options{
				PackageOptions: flag.PackageOptions{
					PkgTypes: []string{types.PkgTypeOS, types.PkgTypeLibrary},
				},
				ScanOptions: flag.ScanOptions{
					Scanners: types.Scanners{types.VulnerabilityScanner},
				},
			},
			expectDisabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := disabledAnalyzers(tt.opts)
			if tt.expectDisabled {
				assert.True(t, slices.Contains(got, analyzer.TypeJar),
					"TypeJar should be in disabled analyzers")
			} else {
				assert.False(t, slices.Contains(got, analyzer.TypeJar),
					"TypeJar should NOT be in disabled analyzers")
			}
		})
	}
}
