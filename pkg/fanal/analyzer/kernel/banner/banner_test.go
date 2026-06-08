package banner

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/kernel/banner"
)

func TestPostAnalyze(t *testing.T) {
	a := &kernelBannerAnalyzer{}
	ctx := context.Background()

	tests := []struct {
		name string
		fs   fstest.MapFS
		want string
	}{
		{
			name: "kern.log only",
			fs: fstest.MapFS{
				"var/log/kern.log": &fstest.MapFile{
					Data: []byte("Apr 26 12:34:56 host kernel: [    0.000000] Linux version 4.18.0-553.el8.x86_64 (build) #1\n"),
				},
			},
			want: "4.18.0-553.el8.x86_64",
		},
		{
			// Regression: append-only kern.log carries the most recent
			// boot's banner at the tail. /var/log/dmesg can be stale
			// (some distros do not regenerate it on every boot), so
			// kern.log must take priority over dmesg.
			name: "kern.log preferred over stale dmesg",
			fs: fstest.MapFS{
				"var/log/dmesg": &fstest.MapFile{
					// Stale: leftover from a previous 1012 boot.
					Data: []byte("[    0.000000] Linux version 6.17.0-1012-aws (build) #1\n"),
				},
				"var/log/kern.log": &fstest.MapFile{
					// Two boots; LAST entry is the running kernel (1010).
					Data: []byte(strings.Join([]string{
						"2026-04-28T12:00:00 host kernel: Linux version 6.17.0-1012-aws (build) (gcc) #1",
						"2026-04-28T14:00:00 host kernel: Linux version 6.17.0-1010-aws (build) (gcc) #2",
						"",
					}, "\n")),
				},
			},
			want: "6.17.0-1010-aws",
		},
		{
			name: "fallback to messages when kern.log missing",
			fs: fstest.MapFS{
				"var/log/messages": &fstest.MapFile{
					Data: []byte("Mar  1 00:00:01 host kernel: [    0.000000] Linux version 4.18.0-553.el8.x86_64 (build)\n"),
				},
			},
			want: "4.18.0-553.el8.x86_64",
		},
		{
			name: "fallback to dmesg only when kern.log and messages missing",
			fs: fstest.MapFS{
				"var/log/dmesg": &fstest.MapFile{
					Data: []byte("[    0.000000] Linux version 6.1.158-178.288.amzn2023.aarch64 (mockbuild) #1\n"),
				},
			},
			want: "6.1.158-178.288.amzn2023.aarch64",
		},
		{
			name: "no relevant files",
			fs:   fstest.MapFS{},
			want: "",
		},
		{
			name: "files exist but contain no banner",
			fs: fstest.MapFS{
				"var/log/dmesg":    &fstest.MapFile{Data: []byte("garbage\nmore garbage\n")},
				"var/log/kern.log": &fstest.MapFile{Data: []byte("nothing useful here\n")},
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
	a := &kernelBannerAnalyzer{}
	for _, p := range banner.SourceFiles {
		if !a.Required(p, nil) {
			t.Errorf("Required(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"etc/passwd", "boot/vmlinuz"} {
		if a.Required(p, nil) {
			t.Errorf("Required(%q) = true, want false", p)
		}
	}
}
