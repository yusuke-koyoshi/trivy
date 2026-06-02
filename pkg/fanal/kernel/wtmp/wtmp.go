// Package wtmp extracts the running kernel release from /var/log/wtmp, the
// binary boot/login record file written by systemd-update-utmp.
//
// This is the highest-confidence offline source: systemd-update-utmp writes
// uname(2) output verbatim into the ut_host[256] field of each BOOT_TIME
// record (the kernel writes its own release), and the LAST BOOT_TIME record is
// by definition the boot the running kernel performed. wtmp is normally small
// (hundreds of KB; tens of MB on busy hosts), and Parse streams it in constant
// memory and reads it in full, so the latest boot is always reached.
//
// Limitations:
//
//   - Some minimal images (scratch/distroless, Bottlerocket, Talos) lack
//     /var/log/wtmp; the caller falls back to banner / journal / GRUB.
//   - Aggressive logrotate can rotate the active wtmp before the next reboot,
//     leaving the running boot record only in /var/log/wtmp.1; only the active
//     file is consulted.
//   - struct utmpx integer fields are host native-endian. We decode ut_type as
//     little-endian, matching trivy's mainstream arches (x86_64, aarch64,
//     ppc64le). Big-endian hosts (s390x, ppc64 BE) fail the ut_type==BOOT_TIME
//     check on every record and fall through to a lower-priority source.
//     Auto-detection was skipped: BE deployments overlap negligibly with
//     trivy's users and the fallback is graceful.
//
// Format reference: glibc <utmpx.h>. Linux pads legacy utmp to match utmpx, so
// they are byte-compatible; we parse the modern utmpx layout (glibc 2.x+).
package wtmp

import (
	"bytes"
	"encoding/binary"
	"io"
)

// recordSizes are the candidate on-disk sizes of a struct utmpx record across
// arches and glibc versions:
//
//   - 384 bytes: classic glibc layout, 32-bit timeval (most x86_64, and
//     historically all Linux).
//   - 400 bytes: glibc 2.34+ where ut_tv's timeval widened to 64-bit
//     (observed on aarch64 Ubuntu 24.04+).
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

// bootUser is the ut_user value systemd-update-utmp (and older sysv-init /
// upstart) write into BOOT_TIME records. Verifying it guards the dual-size
// scan: without the check, a misaligned 400-byte read over a 384-byte file can
// hit a stray 0x0002 in padding, mistake it for ut_type=BOOT_TIME, and return
// arbitrary offset-76 bytes as ut_host.
var bootUser = []byte("reboot")

// chunkSize is the streaming read window. 64 KB holds many records per syscall
// without a large up-front heap allocation.
const chunkSize = 64 << 10

// Parse reads wtmp records sequentially from the file start and returns the
// kernel release in the LAST BOOT_TIME entry, or "" if none is found.
//
// Records are aligned to the file start; a trailing partial record is ignored
// (logrotate truncation can leave one).
//
// Arches differ in struct size (see recordSizes). When the file length divides
// evenly by exactly one candidate, that size is the only correctly-aligned one
// and is tried first; otherwise we try every candidate and rely on the ut_user
// "reboot" check to reject misaligned false positives.
//
// The file is streamed in constant memory: a scanner per candidate buffers at
// most one record and keeps only the latest BOOT_TIME release. wtmp is read in
// full — the newest boot is at the tail and must not be dropped — without OOM
// risk on a pathologically large or crafted file. (The newest boot is the
// running kernel, and this is the highest-priority source, so a stale early
// record would wrongly outrank the correct journal/banner result.)
func Parse(r io.Reader) string {
	scanners := make(map[int]*recordScanner, len(recordSizes))
	for _, sz := range recordSizes {
		scanners[sz] = newRecordScanner(sz)
	}

	var length int
	chunk := make([]byte, chunkSize)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			length += n
			for _, s := range scanners {
				s.write(chunk[:n])
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ""
		}
	}

	for _, sz := range orderBySizeFit(length) {
		if rel := scanners[sz].lastRelease; rel != "" {
			return rel
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

// recordScanner reassembles fixed-size utmpx records (aligned to the file
// start) from a byte stream and remembers the kernel release of the most
// recent valid BOOT_TIME record. It holds at most one record (sz bytes), so
// memory stays flat regardless of file size — letting Parse read wtmp in full
// and still see the boot at the tail without a size cap.
type recordScanner struct {
	sz          int
	buf         []byte
	lastRelease string
}

func newRecordScanner(sz int) *recordScanner {
	return &recordScanner{sz: sz, buf: make([]byte, 0, sz)}
}

// write feeds stream bytes in, evaluating each record once its sz bytes arrive
// then dropping it. Trailing bytes that never complete a record stay in buf
// and are ignored.
func (s *recordScanner) write(p []byte) {
	for len(p) > 0 {
		// Fast path: evaluate a whole record in place when buf is empty, no copy.
		if len(s.buf) == 0 && len(p) >= s.sz {
			s.eval(p[:s.sz])
			p = p[s.sz:]
			continue
		}
		take := min(s.sz-len(s.buf), len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		if len(s.buf) == s.sz {
			s.eval(s.buf)
			s.buf = s.buf[:0]
		}
	}
}

// eval updates lastRelease when rec is a genuine BOOT_TIME entry:
// ut_type==BOOT_TIME, ut_user starts with "reboot" (guards against misaligned
// false positives), and ut_host is non-empty.
func (s *recordScanner) eval(rec []byte) {
	if int16(binary.LittleEndian.Uint16(rec[offType:])) != bootTime {
		return
	}
	if !bytes.HasPrefix(rec[offUser:offUser+lenUser], bootUser) {
		return
	}
	host := rec[offHost : offHost+lenHost]
	if i := bytes.IndexByte(host, 0); i >= 0 {
		host = host[:i]
	}
	if h := string(bytes.TrimSpace(host)); h != "" {
		s.lastRelease = h
	}
}

// Path is the canonical location of the active wtmp file.
const Path = "var/log/wtmp"
