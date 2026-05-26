// Package banner extracts the kernel release string ("uname -r") from boot
// log files. Used by the offline VM scan path where /proc is unavailable.
//
// The kernel writes a fixed banner at boot time. Two on-disk forms occur:
//
//   - Raw dmesg ring buffer dump (e.g. /var/log/dmesg) preserves the kernel
//     monotonic timestamp:
//
//     [    0.000000] Linux version 5.15.0-92-generic (build@host) (gcc ...
//
//   - syslog/journald-forwarded kernel facility messages (/var/log/kern.log,
//     /var/log/syslog) prepend a syslog header, sometimes preserving and
//     sometimes stripping the kernel timestamp:
//
//     Apr 26 12:34:56 host kernel: [    0.000000] Linux version 5.15.0-...
//     2026-04-28T14:45:03+00:00 host kernel: Linux version 6.17.0-1012-aws ...
//
// The regex requires either the kernel monotonic timestamp `[ N.N]` or the
// syslog `kernel:` facility marker before the literal `Linux version`. This
// rejects user-space mentions of "Linux version X" that creep into the same
// log files (apt install / update-grub / dpkg trigger output), which would
// otherwise cause us to pick up a non-running kernel release.
package banner

import (
	"bufio"
	"io"
	"regexp"
)

// linuxVersion matches a kernel-facility banner line and captures the
// release string. The lookbehind-equivalent `(?:kernel:\s+|\[\s*\d[\d.]*\]\s+)`
// enforces that the message originated from the kernel ring buffer, not
// from a user-space process that happens to mention a kernel version.
var linuxVersion = regexp.MustCompile(`(?:kernel:\s+|\[\s*\d[\d.]*\]\s+)Linux version (\S+)`)

// SourceFiles lists the boot-log files that may carry the kernel banner,
// in descending preference order.
//
// Order rationale: append-only syslog/rsyslog outputs come first because
// the LAST `Linux version` line in such a file is guaranteed to be the
// most recent boot's banner.
//
//   - /var/log/kern.log: kernel facility output on Debian/Ubuntu — the
//     most kernel-authoritative file when present.
//   - /var/log/messages: catch-all syslog on RHEL family.
//   - /var/log/syslog: Ubuntu's catch-all destination. Consulted after
//     kern.log because both are written by the same rsyslog pipeline
//     and kern.log is kernel-dedicated.
//   - /var/log/dmesg: static dump of the kernel ring buffer. Some
//     distros (notably modern Ubuntu) do not consistently regenerate
//     it at every boot, so its content can lag behind the actually
//     running kernel. Consulted last as a fallback.
var SourceFiles = []string{
	"var/log/kern.log",
	"var/log/messages",
	"var/log/syslog",
	"var/log/dmesg",
}

// Parse scans r for kernel banner lines and returns the release string from
// the LAST match. Returns "" if no banner is found.
//
// kern.log and messages are appended on every boot, so a long-lived VM may
// have multiple "Linux version" lines. The most recent boot's banner is
// the last occurrence in the file. dmesg only contains the most recent
// boot, so first/last are equivalent there.
func Parse(r io.Reader) string {
	var release string
	s := bufio.NewScanner(r)
	// Lines in messages can be longer than the default 64KB scanner buffer
	// when verbose subsystems (e.g. nvidia, btrfs) dump structured data.
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		if m := linuxVersion.FindSubmatch(s.Bytes()); m != nil {
			release = string(m[1])
		}
	}
	// Discard any partial release on I/O failure so the analyzer falls
	// back to the next priority file rather than trusting a half-read log.
	if s.Err() != nil {
		return ""
	}
	return release
}
