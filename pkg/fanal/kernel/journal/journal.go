// Package journal extracts the running kernel release from systemd's
// binary journal files.
//
// On distributions that route kernel messages exclusively to journald
// (Amazon Linux 2023, RHEL 8+, Fedora, recent Ubuntu without rsyslog),
// the kernel banner — the line `Linux version <release>` the kernel
// prints at boot — is stored only in /var/log/journal/<machine-id>/
// system.journal. There is no /var/log/dmesg or /var/log/messages text
// file the regular banner parser can read.
//
// Strategy: byte-scan the journal file for the field payload prefix
// "MESSAGE=Linux version " and return the release token from the LAST
// occurrence. systemd journal files are append-only, so the last match
// in file order is the most recent boot's banner. The scan reads the
// file in fixed-size chunks with an overlap buffer, so memory use stays
// bounded regardless of journal size (default systemd cap is 128 MB but
// custom configs reach multiple GB).
//
// Limitations:
//
//   - Compressed entries are skipped. systemd compresses individual Data
//     objects with LZ4 (or XZ/ZSTD) when their payload exceeds the
//     `Compress=` threshold, default 512 bytes. The kernel banner is
//     typically ~200-300 bytes and falls under the threshold, so it is
//     stored uncompressed and the byte-scan finds it. Configurations
//     with a lower threshold or unusually verbose kernel banners may
//     compress the message and be missed; the caller falls back to the
//     GRUB heuristic in that case.
//
//   - Rotated archives (system@*.journal~) are not consulted. Only the
//     active system.journal is scanned. A long-running host that has
//     rotated its current boot's banner into an archive will not be
//     detected through this parser.
package journal

import (
	"bytes"
	"io"
)

const banner = "MESSAGE=Linux version "

// Pattern is the glob (and fs.Glob-compatible) match for the active
// systemd system journal.
const Pattern = "var/log/journal/*/system.journal"

// chunkSize is the streaming read window. 1 MB keeps memory bounded for
// multi-GB journals while staying large enough that the per-chunk
// overhead of carrying overlap forward is negligible.
const chunkSize = 1 << 20

// maxRelease bounds how many bytes after the banner prefix we will scan
// for the release token. uname releases are at most ~65 bytes; allow
// generous headroom for vendor-tagged builds.
const maxRelease = 256

// overlap is the number of bytes to carry from the end of one chunk to
// the start of the next, so a banner straddling a chunk boundary is
// still detected. The full match worst-case is:
//
//	"MESSAGE=Linux version " + <release up to maxRelease bytes> + " ("
//	└── len(banner) ─────────┘  └── maxRelease ─────────────────┘  └ 2 ┘
//
// so the overlap window equals len(banner) + maxRelease + 2 (the two
// trailing bytes of the kernel-banner suffix verified in
// lastBannerInWindow). Anything shorter risks losing a banner whose
// release token spans the boundary.
const overlap = len(banner) + maxRelease + 2

// Parse byte-scans a systemd journal file for the kernel banner Data
// object payload and returns the release token from the LAST match
// whose immediately-trailing bytes look like the kernel banner suffix
// `<release> (...`. The trailing ` (` is the open paren of the build
// host parenthesized field that the kernel always emits and that
// user-space log messages mentioning a kernel version (apt install
// output, update-grub, etc.) typically lack. Without this guard a
// later user-space log line about an installed-but-not-running kernel
// would override the actual boot banner of the running kernel.
//
// Reads the input in 1 MB chunks with an overlap window so memory use
// is O(chunkSize) regardless of file size. Returns "" when no
// banner-formatted entry is found.
func Parse(r io.Reader) string {
	prefix := []byte(banner)
	var release string
	buf := make([]byte, chunkSize)
	// Reuse a single backing array for the per-chunk window so each
	// iteration does not re-allocate ~chunkSize bytes via append.
	window := make([]byte, 0, overlap+chunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			// window retains the carried tail from the previous chunk;
			// append the new chunk in-place using the preallocated cap.
			window = append(window, buf[:n]...)
			if rel, ok := lastBannerInWindow(window, prefix); ok {
				release = rel
			}
			// Preserve the tail so a banner spanning the boundary
			// between this chunk and the next can still match.
			if len(window) > overlap {
				window = append(window[:0], window[len(window)-overlap:]...)
			}
		}
		if err == io.EOF {
			return release
		}
		if err != nil {
			// Discard any partial release on I/O failure so the analyzer
			// falls back to a lower-priority source rather than trusting
			// a half-read scan.
			return ""
		}
	}
}

// lastBannerInWindow scans data for the LAST occurrence of prefix
// followed by a release token and the kernel-banner suffix " (".
// Returns the release and true if found; "" / false otherwise.
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
