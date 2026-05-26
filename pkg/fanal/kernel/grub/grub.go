// Package grub extracts the running kernel release from GRUB persistent
// state on offline scan targets that lack a boot log banner.
//
// On RHEL 8+, Fedora, Amazon Linux 2023 and other modern distros the
// kernel ring buffer is logged via systemd-journald only — there is no
// /var/log/dmesg or /var/log/messages text file the banner parser can
// read. GRUB however persists which boot loader entry was last selected
// in /boot/grub2/grubenv as the `saved_entry=<machine-id>-<release>`
// variable, and each entry in /boot/loader/entries/<saved_entry>.conf
// declares its kernel `version`. Combining these two yields the same
// release string `uname -r` would report.
//
// Caveat: if the user runs `grub-set-default <other>` after boot but
// before reboot, `saved_entry` reflects the next-boot intent rather
// than the currently-running kernel. In that window — uncommon outside
// staging — the value is "GRUB's recorded boot target" rather than the
// actually-running kernel. We treat the typical case (saved_entry =
// last-booted entry) as the running-kernel signal.
package grub

import (
	"bufio"
	"io"
	"strings"
)

// ParseGrubenv extracts variables from /boot/grub2/grubenv. The file is a
// fixed 1KB block of `key=value` lines; comment lines start with '#' and
// trailing '#' padding fills unused space. Returns the value of the
// requested key, or "" if absent.
func ParseGrubenv(r io.Reader, key string) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ParseBLSVersion extracts the kernel release from a Boot Loader Spec
// entry file (typically under /boot/loader/entries/). Prefers the
// explicit `version` field; falls back to extracting from the `linux`
// line's vmlinuz path.
func ParseBLSVersion(r io.Reader) string {
	var version, linux string
	s := bufio.NewScanner(r)
	for s.Scan() {
		// BLS Type#1 separates key from value with one or more whitespace
		// characters (space or tab); Fields handles both.
		fields := strings.Fields(s.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "version":
			version = fields[1]
		case "linux":
			linux = fields[1]
		}
	}
	if s.Err() != nil {
		return ""
	}
	if version != "" {
		return version
	}
	// Fallback: extract release from the rightmost vmlinuz-<release> path
	// segment of the `linux` directive.
	if i := strings.LastIndex(linux, "vmlinuz-"); i >= 0 {
		return linux[i+len("vmlinuz-"):]
	}
	return ""
}
