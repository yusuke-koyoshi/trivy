package flag_test

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestAzureFlagGroup_ToOptions(t *testing.T) {
	tests := []struct {
		name        string
		sasDuration string
		want        time.Duration
		wantErr     string
	}{
		{
			name:        "set",
			sasDuration: "3h",
			want:        3 * time.Hour,
		},
		{
			name:        "too short",
			sasDuration: "500ms",
			wantErr:     "--azure-sas-duration must be between 1s and 1440h0m0s",
		},
		{
			name:        "longer than Azure grants",
			sasDuration: "1441h",
			wantErr:     "--azure-sas-duration must be between 1s and 1440h0m0s",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			viper.Set("azure.sas-duration", tt.sasDuration)

			flags := flag.Flags{flag.NewAzureFlagGroup()}
			got, err := flags.ToOptions(nil)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.SASDuration)
		})
	}
}
