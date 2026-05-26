// Package grub is a PostAnalyzer that detects the running kernel release
// from GRUB persistent state, used as a last-resort fallback when neither
// boot log banners nor systemd journal yield a release.
//
// It exists for offline scan targets where the regular banner parser
// cannot find /var/log/dmesg / kern.log / messages and the journal
// parser cannot find an uncompressed kernel banner — e.g. configs with
// volatile journald and rsyslog disabled.
//
// Strategy:
//
//  1. Read /boot/grub2/grubenv (or /boot/grub/grubenv) to obtain
//     `saved_entry=<machine-id>-<release>` — the entry GRUB writes after
//     a successful boot.
//  2. Open /boot/loader/entries/<saved_entry>.conf and read its
//     `version` field, falling back to the `linux` directive's
//     vmlinuz-<release> path.
//
// AnalysisResult.Merge ranks GRUB below banner and journal in
// runningKernelReleaseSourcePriority, so a release reported here is
// silently overridden whenever a higher-confidence analyzer also
// produces one.
//
// Caveat: if `grub-set-default` is invoked after boot but before reboot,
// `saved_entry` reflects the next-boot intent rather than the running
// kernel for that brief window. In normal operation banner or journal
// will provide the actual running release and override this value via
// the merge priority; the residual risk is configurations where neither
// of those sources yields a release AND `grub-set-default` was used
// post-boot.
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

// grubenvPaths lists the locations of the GRUB environment block. Distros
// historically split between /boot/grub (legacy) and /boot/grub2 (GRUB 2).
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

// readSavedEntry returns the saved_entry value along with the grubenv
// path it was read from, so the caller can log the actual source rather
// than a hardcoded path.
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
