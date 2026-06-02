// Package banner extracts the kernel release string ("uname -r") from boot
// log files, for the offline VM scan path where /proc is unavailable.
//
// The boot banner occurs in two on-disk forms:
//
//   - Raw dmesg ring buffer dump (e.g. /var/log/dmesg), with the kernel
//     monotonic timestamp:
//
//     [    0.000000] Linux version 5.15.0-92-generic (build@host) (gcc ...
//
//   - syslog/journald-forwarded kernel facility messages (/var/log/kern.log,
//     /var/log/syslog), with a syslog header and sometimes the kernel
//     timestamp stripped:
//
//     Apr 26 12:34:56 host kernel: [    0.000000] Linux version 5.15.0-...
//     2026-04-28T14:45:03+00:00 host kernel: Linux version 6.17.0-1012-aws ...
//
// The regex requires the kernel timestamp `[ N.N]` or the syslog `kernel:`
// marker before `Linux version`, rejecting user-space mentions (apt install /
// update-grub / dpkg trigger output) that would otherwise yield a non-running
// release.
package banner

import (
	"bufio"
	"io"
	"regexp"
)

// linuxVersion matches a kernel-facility banner line and captures the release.
// The `(?:kernel:\s+|\[\s*\d[\d.]*\]\s+)` prefix enforces kernel-ring-buffer
// origin, not a user-space process mentioning a kernel version.
var linuxVersion = regexp.MustCompile(`(?:kernel:\s+|\[\s*\d[\d.]*\]\s+)Linux version (\S+)`)

// SourceFiles lists the boot-log files that may carry the kernel banner, in
// descending preference order. Append-only syslog/rsyslog outputs come first
// because their LAST `Linux version` line is the most recent boot's banner.
//
//   - /var/log/kern.log: kernel facility output on Debian/Ubuntu — most
//     authoritative when present.
//   - /var/log/messages: catch-all syslog on RHEL family.
//   - /var/log/syslog: Ubuntu's catch-all. After kern.log: same rsyslog
//     pipeline, but kern.log is kernel-dedicated.
//   - /var/log/dmesg: static ring-buffer dump. Some distros (notably modern
//     Ubuntu) don't regenerate it every boot, so it can lag the running
//     kernel — consulted last.
var SourceFiles = []string{
	"var/log/kern.log",
	"var/log/messages",
	"var/log/syslog",
	"var/log/dmesg",
}

// Parse scans r for kernel banner lines and returns the release from the LAST
// match, or "" if none is found.
//
// kern.log/messages are appended every boot, so a long-lived VM has multiple
// "Linux version" lines; the last is the most recent boot. dmesg holds only
// the most recent boot, so first/last are equivalent there.
func Parse(r io.Reader) string {
	var release string
	s := bufio.NewScanner(r)
	// Lines can exceed the default 64KB scanner buffer.
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		if m := linuxVersion.FindSubmatch(s.Bytes()); m != nil {
			release = string(m[1])
		}
	}
	// Don't trust a partially read log on I/O failure.
	if s.Err() != nil {
		return ""
	}
	return release
}
