// Package banner is a PostAnalyzer that detects an offline target's running
// kernel release by parsing boot log banners.
//
// Used mainly by `trivy vm` and `trivy rootfs <other-host>` where /proc is
// unavailable. The release feeds pkg/scan/ospkg's kernel labeling to suppress
// vulns for non-running kernel packages.
//
// Limitation: with /var on a separate partition, each partition is walked
// independently, so /var/log/* appears at the partition root (e.g. "log/dmesg"
// not "var/log/dmesg") and is missed. Most cloud AMIs are single-partition and
// unaffected.
package banner

import (
	"context"
	"io/fs"
	"os"
	"slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/kernel/banner"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeKernelBanner, newAnalyzer)
}

const version = 1

type kernelBannerAnalyzer struct{}

func newAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &kernelBannerAnalyzer{}, nil
}

func (a *kernelBannerAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	for _, p := range banner.SourceFiles {
		release, err := readBanner(input.FS, p)
		if err != nil || release == "" {
			continue
		}
		log.Debug("kernel-banner detected running release",
			log.String("source", p), log.String("release", release))
		return &analyzer.AnalysisResult{RunningKernelRelease: release}, nil
	}
	return nil, nil
}

func readBanner(fsys fs.FS, path string) (string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return banner.Parse(f), nil
}

func (a *kernelBannerAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(banner.SourceFiles, filePath)
}

func (a *kernelBannerAnalyzer) Type() analyzer.Type {
	return analyzer.TypeKernelBanner
}

func (a *kernelBannerAnalyzer) Version() int {
	return version
}

func (a *kernelBannerAnalyzer) StaticPaths() []string {
	return banner.SourceFiles
}
