// Package journal is a PostAnalyzer that detects the running kernel
// release from systemd's persistent binary journal.
//
// On distros that route kernel messages exclusively to journald (Amazon
// Linux 2023, RHEL 8+, Fedora, recent Ubuntu without rsyslog), the
// kernel banner ("Linux version <release> ...") is logged to
// /var/log/journal/<machine-id>/system.journal as a Data object. The
// regular boot-log banner parser at pkg/fanal/analyzer/kernel/banner
// cannot find a release on these distros because /var/log/dmesg,
// /var/log/kern.log and /var/log/messages are not produced by default.
//
// The journal binary format stores each MESSAGE field's payload as
// "MESSAGE=<text>" inside a Data object. A byte-scan of the journal for
// the prefix "MESSAGE=Linux version " locates the kernel banner; the
// LAST occurrence in the append-only file is the most recent boot.
//
// Compressed entries are skipped. The kernel banner is short (~200 bytes)
// and falls under journald's default 512-byte compression threshold, so
// it is normally stored uncompressed. Custom configurations that lower
// the threshold or unusually verbose banners may be missed; the caller
// falls back to the GRUB heuristic in that case.
package journal

import (
	"context"
	"io/fs"
	"os"
	"path"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/kernel/journal"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeKernelJournal, newAnalyzer)
}

const version = 1

type kernelJournalAnalyzer struct{}

func newAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &kernelJournalAnalyzer{}, nil
}

func (a *kernelJournalAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	matches, err := fs.Glob(input.FS, journal.Pattern)
	if err != nil || len(matches) == 0 {
		return nil, nil
	}
	for _, p := range matches {
		release, err := readJournal(input.FS, p)
		if err != nil || release == "" {
			continue
		}
		log.Debug("kernel-journal detected running release",
			log.String("source", p), log.String("release", release))
		return &analyzer.AnalysisResult{RunningKernelRelease: release}, nil
	}
	return nil, nil
}

func readJournal(fsys fs.FS, p string) (string, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return journal.Parse(f), nil
}

func (a *kernelJournalAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// path.Match's "*" does not cross "/", so this matches any direct
	// machine-id child without descending into nested directories.
	matched, _ := path.Match(journal.Pattern, filePath)
	return matched
}

func (a *kernelJournalAnalyzer) Type() analyzer.Type {
	return analyzer.TypeKernelJournal
}

func (a *kernelJournalAnalyzer) Version() int {
	return version
}
