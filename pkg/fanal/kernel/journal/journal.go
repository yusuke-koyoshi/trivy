// Package journal extracts the running kernel release from systemd's binary
// journal files.
//
// On distros that route kernel messages exclusively to journald (Amazon Linux
// 2023, RHEL 8+, Fedora, recent Ubuntu without rsyslog), the kernel banner
// (`Linux version <release>`) is stored only in
// /var/log/journal/<machine-id>/system.journal — there is no /var/log/dmesg or
// /var/log/messages for the regular banner parser to read.
//
// Strategy: byte-scan the file for the field payload prefix "MESSAGE=Linux
// version " and return the release from the LAST occurrence (journal files are
// append-only, so the last match is the most recent boot). The scan reads
// fixed-size chunks with an overlap buffer, so memory stays bounded regardless
// of journal size (default cap 128 MB, but custom configs reach multiple GB).
//
// Limitations:
//
//   - Compressed entries are skipped. systemd compresses Data objects (LZ4,
//     XZ, or ZSTD) above the `Compress=` threshold (default 512 bytes). The
//     banner is ~200-300 bytes, under the threshold, so it stays uncompressed
//     and is found. A lowered threshold or unusually verbose banners may
//     compress it and be missed; the caller then falls back to GRUB.
//
//   - Rotated archives (system@*.journal~) are not consulted; only the active
//     system.journal is scanned. A banner rotated into an archive is missed.
package journal

import (
	"bytes"
	"io"
)

const banner = "MESSAGE=Linux version "

// Pattern is the fs.Glob-compatible match for the active systemd journal.
const Pattern = "var/log/journal/*/system.journal"

// chunkSize is the streaming read window. 1 MB bounds memory for multi-GB
// journals while keeping per-chunk overlap-carry overhead negligible.
const chunkSize = 1 << 20

// maxRelease bounds the bytes scanned after the banner prefix for the release
// token. uname releases are at most ~65 bytes; headroom for vendor tags.
const maxRelease = 256

// overlap is the bytes carried from one chunk's end to the next's start so a
// banner straddling a boundary is still detected. Worst-case full match:
//
//	"MESSAGE=Linux version " + <release up to maxRelease bytes> + " ("
//	└── len(banner) ─────────┘  └── maxRelease ─────────────────┘  └ 2 ┘
//
// i.e. len(banner) + maxRelease + 2 (the trailing suffix bytes verified in
// lastBannerInWindow). Anything shorter risks losing a boundary-spanning banner.
const overlap = len(banner) + maxRelease + 2

// Parse byte-scans a systemd journal for the kernel banner Data object payload
// and returns the release from the LAST match whose trailing bytes look like
// the banner suffix `<release> (...`. The ` (` opens the build-host field the
// kernel always emits but user-space mentions (apt install, update-grub, etc.)
// typically lack; without this guard a later user-space line about an
// installed-but-not-running kernel would override the real boot banner.
//
// Reads 1 MB chunks with an overlap window, so memory is O(chunkSize)
// regardless of file size. Returns "" when no banner entry is found.
func Parse(r io.Reader) string {
	prefix := []byte(banner)
	var release string
	buf := make([]byte, chunkSize)
	// Reuse one backing array for the window to avoid re-allocating.
	window := make([]byte, 0, overlap+chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			window = append(window, buf[:n]...)
			if rel, ok := lastBannerInWindow(window, prefix); ok {
				release = rel
			}
			// Carry the tail forward so a boundary-spanning banner still matches.
			if len(window) > overlap {
				window = append(window[:0], window[len(window)-overlap:]...)
			}
		}
		if err == io.EOF {
			return release
		}
		if err != nil {
			// Don't trust a half-read scan on I/O failure.
			return ""
		}
	}
}

// lastBannerInWindow returns the release from the LAST occurrence of prefix
// followed by a release token and the banner suffix " (", with true; else
// "" / false.
func lastBannerInWindow(data, prefix []byte) (string, bool) {
	tail := data
	for {
		idx := bytes.LastIndex(tail, prefix)
		if idx < 0 {
			return "", false
		}
		start := idx + len(prefix)
		end := start
		for end < len(data) && data[end] > 0x20 && data[end] < 0x7f {
			end++
		}
		if end+1 < len(data) && data[end] == ' ' && data[end+1] == '(' {
			return string(data[start:end]), true
		}
		tail = data[:idx]
	}
}
