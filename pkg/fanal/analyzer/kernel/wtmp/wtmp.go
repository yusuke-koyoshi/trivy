// Package wtmp is a PostAnalyzer that detects the running kernel release from
// /var/log/wtmp.
//
// systemd-update-utmp.service writes the kernel release (uname -r) to the
// ut_host field of every BOOT_TIME record, making wtmp the smallest and
// highest-confidence offline source on standard Linux distros. Unlike the
// journal it doesn't grow unbounded, and the active file always holds the
// current boot's record (default logrotate keeps it at least a month).
package wtmp

import (
	"context"
	"io/fs"
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/kernel/wtmp"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeKernelWtmp, newAnalyzer)
}

const version = 1

type kernelWtmpAnalyzer struct{}

func newAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &kernelWtmpAnalyzer{}, nil
}

func (a *kernelWtmpAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	release, err := readWtmp(input.FS, wtmp.Path)
	if err != nil || release == "" {
		return nil, nil
	}
	log.Debug("kernel-wtmp detected running release",
		log.String("source", wtmp.Path), log.String("release", release))
	return &analyzer.AnalysisResult{RunningKernelRelease: release}, nil
}

func readWtmp(fsys fs.FS, p string) (string, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return wtmp.Parse(f), nil
}

func (a *kernelWtmpAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filePath == wtmp.Path
}

func (a *kernelWtmpAnalyzer) Type() analyzer.Type {
	return analyzer.TypeKernelWtmp
}

func (a *kernelWtmpAnalyzer) Version() int {
	return version
}

func (a *kernelWtmpAnalyzer) StaticPaths() []string {
	return []string{wtmp.Path}
}
