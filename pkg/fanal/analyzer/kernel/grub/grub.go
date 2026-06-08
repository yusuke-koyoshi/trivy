// Package grub is a PostAnalyzer that detects the running kernel release from
// GRUB persistent state — a last resort when neither boot log banners nor the
// systemd journal yield one (e.g. volatile journald with rsyslog disabled).
//
// Strategy:
//
//  1. Read /boot/grub2/grubenv (or /boot/grub/grubenv) for
//     `saved_entry=<machine-id>-<release>`, the entry GRUB writes after a
//     successful boot.
//  2. Open /boot/loader/entries/<saved_entry>.conf and read its `version`
//     field, falling back to the `linux` directive's vmlinuz-<release> path.
//
// AnalysisResult.Merge ranks GRUB below banner and journal, so a release here
// is overridden whenever a higher-confidence analyzer also produces one.
//
// Caveat: a `grub-set-default` between boot and reboot makes `saved_entry`
// next-boot intent rather than the running kernel. Normally banner or journal
// overrides this via merge priority; the residual risk is configs where
// neither yields a release AND `grub-set-default` was used post-boot.
package grub

import (
	"context"
	"io/fs"
	"os"
	"path"
	"slices"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/kernel/grub"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeKernelGRUB, newAnalyzer)
}

const version = 1

// grubenvPaths lists GRUB environment block locations: /boot/grub (legacy) and
// /boot/grub2 (GRUB 2).
var grubenvPaths = []string{
	"boot/grub2/grubenv",
	"boot/grub/grubenv",
}

// blsEntriesDir is the standard location of Boot Loader Spec entries.
const blsEntriesDir = "boot/loader/entries"

type kernelGRUBAnalyzer struct{}

func newAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &kernelGRUBAnalyzer{}, nil
}

func (a *kernelGRUBAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	savedEntry, sourcePath := readSavedEntry(input.FS)
	if savedEntry == "" {
		return nil, nil
	}
	release, err := readBLSVersion(input.FS, path.Join(blsEntriesDir, savedEntry+".conf"))
	if err != nil || release == "" {
		return nil, nil
	}
	log.Debug("kernel-grub detected running release",
		log.String("source", sourcePath), log.String("release", release))
	return &analyzer.AnalysisResult{RunningKernelRelease: release}, nil
}

// readSavedEntry returns the saved_entry value and the grubenv path it came
// from, so the caller can log the actual source.
func readSavedEntry(fsys fs.FS) (entry, sourcePath string) {
	for _, p := range grubenvPaths {
		f, err := fsys.Open(p)
		if err != nil {
			continue
		}
		entry = grub.ParseGrubenv(f, "saved_entry")
		_ = f.Close()
		if entry != "" {
			return entry, p
		}
	}
	return "", ""
}

func readBLSVersion(fsys fs.FS, p string) (string, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return grub.ParseBLSVersion(f), nil
}

func (a *kernelGRUBAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if slices.Contains(grubenvPaths, filePath) {
		return true
	}
	matched, _ := path.Match(blsEntriesDir+"/*.conf", filePath)
	return matched
}

func (a *kernelGRUBAnalyzer) Type() analyzer.Type {
	return analyzer.TypeKernelGRUB
}

func (a *kernelGRUBAnalyzer) Version() int {
	return version
}
