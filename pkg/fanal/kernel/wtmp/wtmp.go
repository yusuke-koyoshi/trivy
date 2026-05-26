// Package wtmp extracts the running kernel release from /var/log/wtmp,
// the binary boot/login record file written by systemd-update-utmp on
// modern Linux distributions.
//
// The kernel release is the highest-confidence offline source available
// because:
//
//   - systemd-update-utmp writes uname(2) output verbatim into the
//     ut_host[256] field of each BOOT_TIME record, so the value is
//     authoritative ("the kernel writes its own release").
//   - The active /var/log/wtmp is a small file (typically a few hundred
//     KB) regardless of host uptime, unlike journals which can be tens
//     to hundreds of MB and rotate the boot banner out of view.
//   - The LAST BOOT_TIME record is, by definition, the boot that the
//     currently-running kernel performed.
//
// Limitations:
//
//   - Some minimal images (scratch / distroless containers, Bottlerocket,
//     Talos) ship without /var/log/wtmp; the caller falls back to banner
//     / journal / GRUB sources.
//   - Long uptimes plus aggressive logrotate can rotate the active
//     wtmp before the next reboot, leaving the running boot record only
//     in /var/log/wtmp.1; only the active file is consulted here.
//   - The integer fields in struct utmpx are written in the host's
//     native byte order. We decode ut_type as little-endian, which
//     matches every architecture in trivy's mainstream support
//     (x86_64, aarch64, ppc64le). Files written by big-endian hosts
//     (s390x, ppc64 BE) will fail the ut_type==BOOT_TIME check on
//     every record and the parser falls through to a lower-priority
//     source. Auto-detection was considered and skipped: the BE
//     deployments overlap negligibly with trivy's user base and the
//     fallback behavior is graceful.
//
// Format reference: glibc <utmpx.h>. Linux pads the legacy utmp struct
// to match utmpx so the two are byte-compatible. We parse the modern
// utmpx layout used since glibc 2.x.
package wtmp

import (
	"bytes"
	"encoding/binary"
	"io"
)

// recordSizes are the candidate on-disk sizes of a Linux struct utmpx
// record across architectures and glibc versions:
//
//   - 384 bytes: classic glibc layout with 32-bit timeval (most x86_64
//     and historically all Linux installs).
//   - 400 bytes: glibc 2.34+ on architectures where the timeval inside
//     ut_tv was widened to 64 bits (observed on aarch64 Ubuntu 24.04+).
//
// Parse picks the size that produces sensible BOOT_TIME records.
var recordSizes = []int{400, 384}

// bootTime is ut_type for boot records (UT_BOOT_TIME in <utmpx.h>).
const bootTime = 2

// Field offsets within a record. Derived from <bits/utmpx.h>:
//
//	int16  ut_type        // 0
//	pad    [2]            // 2
//	int32  ut_pid         // 4
//	char   ut_line[32]    // 8
//	char   ut_id[4]       // 40
//	char   ut_user[32]    // 44
//	char   ut_host[256]   // 76
//	... (timestamps and addr_v6 follow)
const (
	offType = 0
	offUser = 44
	lenUser = 32
	offHost = 76
	lenHost = 256
)

// bootUser is the conventional ut_user value systemd-update-utmp (and
// older sysv-init / upstart equivalents) write into BOOT_TIME records.
// Verifying this guards the dual-size scan against false positives:
// without the check, a misaligned 400-byte read across a 384-byte file
// can pick up a stray 0x0002 in random padding bytes, mistake it for
// ut_type=BOOT_TIME, and return arbitrary bytes from offset 76 as if
// they were ut_host.
var bootUser = []byte("reboot")

// chunkSize is the streaming read window. 64 KB is large enough to
// hold many records per syscall without committing the parser to a
// large heap allocation up front.
const chunkSize = 64 << 10

// maxFileSize bounds how much of wtmp the parser will buffer. Standard
// logrotate keeps the active wtmp under a few MB, so 50 MB is a
// generous defense-in-depth cap; a larger file is treated as if it
// ended at this offset and any trailing records (likely the most
// recent BOOT_TIME) are dropped rather than risk OOM on a malformed
// or unrotated host. Variable rather than const so tests can shrink it.
var maxFileSize = 50 << 20

// Parse reads wtmp records sequentially from the start of the file and
// returns the kernel release recorded in the LAST BOOT_TIME entry, or
// "" if none is found.
//
// Records are aligned to the file start; trailing bytes that don't
// complete a full record are ignored (some kernels / userspace tools
// leave a partial tail when wtmp is truncated by logrotate).
//
// Architectures differ in struct size (see recordSizes). When the file
// length divides evenly by exactly one candidate size that size is the
// only one that produces correctly aligned records, so we try it first;
// otherwise we try every candidate and rely on each scan's ut_user
// "reboot" sanity check to reject misaligned false positives.
//
// Reads are chunked (chunkSize bytes per syscall) and capped at
// maxFileSize so a pathologically large or unrotated wtmp cannot
// exhaust memory.
func Parse(r io.Reader) string {
	var data []byte
	chunk := make([]byte, chunkSize)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			if room := maxFileSize - len(data); n > room {
				n = room
			}
			data = append(data, chunk[:n]...)
		}
		if len(data) >= maxFileSize {
			break
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ""
		}
	}
	for _, sz := range orderBySizeFit(len(data)) {
		if release := scanRecords(data, sz); release != "" {
			return release
		}
	}
	return ""
}

// orderBySizeFit returns recordSizes reordered so that any candidate
// that divides len evenly comes first. If multiple candidates fit, or
// none do, the original recordSizes order is preserved.
func orderBySizeFit(length int) []int {
	out := make([]int, 0, len(recordSizes))
	for _, sz := range recordSizes {
		if length > 0 && length%sz == 0 {
			out = append(out, sz)
		}
	}
	for _, sz := range recordSizes {
		if length == 0 || length%sz != 0 {
			out = append(out, sz)
		}
	}
	return out
}

// scanRecords iterates fixed-size records starting at offset 0 and
// returns the kernel release from the LAST BOOT_TIME record whose
// ut_user starts with "reboot" and whose ut_host is non-empty. Returns
// "" if no such record is found.
func scanRecords(data []byte, sz int) string {
	var release string
	for off := 0; off+sz <= len(data); off += sz {
		rec := data[off : off+sz]
		if int16(binary.LittleEndian.Uint16(rec[offType:])) != bootTime {
			continue
		}
		if !bytes.HasPrefix(rec[offUser:offUser+lenUser], bootUser) {
			continue
		}
		host := rec[offHost : offHost+lenHost]
		if i := bytes.IndexByte(host, 0); i >= 0 {
			host = host[:i]
		}
		if h := string(bytes.TrimSpace(host)); h != "" {
			release = h
		}
	}
	return release
}

// Path is the canonical location of the active wtmp file.
const Path = "var/log/wtmp"
