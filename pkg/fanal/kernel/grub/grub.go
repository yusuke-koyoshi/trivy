// Package grub extracts the running kernel release from GRUB persistent
// state. It is a last resort for distros that log the kernel banner to
// journald only (RHEL 8+, Fedora, Amazon Linux 2023) with no text log to
// parse. /boot/grub2/grubenv holds `saved_entry=<machine-id>-<release>`
// and the matching /boot/loader/entries/<saved_entry>.conf declares its
// kernel `version`; together they reconstruct `uname -r`.
//
// Caveat: `saved_entry` is the last-selected boot entry, so a
// `grub-set-default` between boot and reboot makes it next-boot intent
// rather than the running kernel — hence this source's low priority.
package grub

import (
	"bufio"
	"io"
	"strings"
)

// ParseGrubenv returns the value of key from /boot/grub2/grubenv, or "" if
// absent. The file is a fixed 1KB block of `key=value` lines with '#' comment
// lines and trailing '#' padding.
func ParseGrubenv(r io.Reader, key string) string {
	s := bufio.NewScanner(r)
	var val string
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			val = strings.TrimSpace(v)
			break
		}
	}
	// Don't trust a partially read file.
	if s.Err() != nil {
		return ""
	}
	return val
}

// ParseBLSVersion extracts the kernel release from a Boot Loader Spec
// entry file (typically under /boot/loader/entries/). Prefers the
// explicit `version` field; falls back to extracting from the `linux`
// line's vmlinuz path.
func ParseBLSVersion(r io.Reader) string {
	var version, linux string
	s := bufio.NewScanner(r)
	for s.Scan() {
		// BLS Type#1 separates key from value with whitespace (space or tab).
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
	// Fall back to the release in the `linux` directive's vmlinuz-<release> path.
	if i := strings.LastIndex(linux, "vmlinuz-"); i >= 0 {
		return linux[i+len("vmlinuz-"):]
	}
	return ""
}
