package journal

import (
	"bytes"
	"context"
	"testing"
	"testing/fstest"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

// synthBanner returns a journal-like blob with the given banner payload
// embedded between header bytes and trailing alignment.
func synthBanner(banners ...string) []byte {
	var buf bytes.Buffer
	buf.WriteString("LPKSHHRH")
	buf.Write(make([]byte, 248))
	for _, b := range banners {
		buf.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		buf.Write([]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		buf.WriteString(b)
		buf.Write([]byte{0x00, 0x00, 0x00})
	}
	return buf.Bytes()
}

func TestPostAnalyze(t *testing.T) {
	a := &kernelJournalAnalyzer{}
	ctx := context.Background()

	tests := []struct {
		name string
		fs   fstest.MapFS
		want string
	}{
		{
			name: "AL2023 active system.journal with current boot banner",
			fs: fstest.MapFS{
				"var/log/journal/ec22ff19161cb00ddacaddc223f52185/system.journal": &fstest.MapFile{
					Data: synthBanner(
						"MESSAGE=Linux version 6.1.141-167.250.amzn2023.aarch64 (mockbuild) (gcc 11.4.0)",
					),
				},
			},
			want: "6.1.141-167.250.amzn2023.aarch64",
		},
		{
			name: "rotated archive is ignored even if it has a banner",
			fs: fstest.MapFS{
				// Rotated archive — ignored by Required().
				"var/log/journal/ec22ff19161cb00ddacaddc223f52185/system@00065084d05a1241.journal~": &fstest.MapFile{
					Data: synthBanner(
						"MESSAGE=Linux version 5.10.0-stale (build) (gcc)",
					),
				},
			},
			want: "",
		},
		{
			name: "user journal is ignored",
			fs: fstest.MapFS{
				"var/log/journal/ec22ff19161cb00ddacaddc223f52185/user-1000.journal": &fstest.MapFile{
					Data: synthBanner(
						"MESSAGE=Linux version 5.10.0-from-user-journal (build) (gcc)",
					),
				},
			},
			want: "",
		},
		{
			name: "multiple boots in same journal: most recent wins",
			fs: fstest.MapFS{
				"var/log/journal/ec22ff19161cb00ddacaddc223f52185/system.journal": &fstest.MapFile{
					Data: synthBanner(
						"MESSAGE=Linux version 5.15.0-89-generic (build@h) (gcc 11)",
						"MESSAGE=Linux version 6.1.141-167.250.amzn2023.aarch64 (mockbuild) (gcc 11.4.0)",
					),
				},
			},
			want: "6.1.141-167.250.amzn2023.aarch64",
		},
		{
			name: "no journal at all",
			fs:   fstest.MapFS{},
			want: "",
		},
		{
			name: "journal exists but no kernel banner (compressed or absent)",
			fs: fstest.MapFS{
				"var/log/journal/ec22ff19161cb00ddacaddc223f52185/system.journal": &fstest.MapFile{
					Data: synthBanner("MESSAGE=systemd[1]: Started something."),
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{FS: tt.fs})
			if err != nil {
				t.Fatalf("PostAnalyze() error = %v", err)
			}
			got := ""
			if res != nil {
				got = res.RunningKernelRelease
			}
			if got != tt.want {
				t.Errorf("RunningKernelRelease = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRequired(t *testing.T) {
	a := &kernelJournalAnalyzer{}
	yes := []string{
		"var/log/journal/ec22ff19161cb00ddacaddc223f52185/system.journal",
		"var/log/journal/abcdef0123456789/system.journal",
	}
	for _, p := range yes {
		if !a.Required(p, nil) {
			t.Errorf("Required(%q) = false, want true", p)
		}
	}
	no := []string{
		// Rotated archive
		"var/log/journal/ec22ff/system@00065084d05a1241-af08ecd5c7cb690b.journal~",
		// User journal
		"var/log/journal/ec22ff/user-1000.journal",
		// Nested subdirectory
		"var/log/journal/ec22ff/sub/system.journal",
		// Top-level journal directory file
		"var/log/journal/system.journal",
		"var/log/messages",
	}
	for _, p := range no {
		if a.Required(p, nil) {
			t.Errorf("Required(%q) = true, want false", p)
		}
	}
}
