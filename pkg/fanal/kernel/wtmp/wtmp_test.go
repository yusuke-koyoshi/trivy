package wtmp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"testing/iotest"
)

// makeRecord builds a single utmpx record with the given type and host
// string, sized for the first (preferred) on-disk layout.
func makeRecord(utType int16, host string) []byte {
	return makeRecordSize(utType, host, recordSizes[0])
}

// makeRecordSize is like makeRecord but lets the test pin a specific
// on-disk record size, used to exercise the dual-size scan's fallback
// path for the legacy 384-byte layout.
//
// BOOT_TIME records get ut_user="reboot" so they pass the parser's
// sanity check; non-BOOT_TIME records leave ut_user zero to mirror what
// systemd-update-utmp writes for non-boot events.
func makeRecordSize(utType int16, host string, sz int) []byte {
	rec := make([]byte, sz)
	binary.LittleEndian.PutUint16(rec[offType:], uint16(utType))
	if utType == bootTime {
		copy(rec[offUser:offUser+lenUser], "reboot")
	}
	copy(rec[offHost:offHost+lenHost], host)
	return rec
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		recs [][]byte
		want string
	}{
		{
			name: "single boot record returns its release",
			recs: [][]byte{
				makeRecord(bootTime, "6.17.0-1010-aws"),
			},
			want: "6.17.0-1010-aws",
		},
		{
			name: "multiple boot records returns the last one",
			recs: [][]byte{
				makeRecord(bootTime, "5.15.0-92-generic"),
				makeRecord(bootTime, "6.17.0-1009-aws"),
				makeRecord(bootTime, "6.17.0-1010-aws"),
			},
			want: "6.17.0-1010-aws",
		},
		{
			name: "non-boot records before/after the boot record are ignored",
			recs: [][]byte{
				makeRecord(7, "ssh-host"),  // USER_PROCESS
				makeRecord(bootTime, "6.17.0-1010-aws"),
				makeRecord(7, "ssh-host2"), // USER_PROCESS, after boot
				makeRecord(8, ""),          // DEAD_PROCESS
			},
			want: "6.17.0-1010-aws",
		},
		{
			name: "boot record with empty ut_host is skipped, fall through to older",
			recs: [][]byte{
				makeRecord(bootTime, "6.17.0-1010-aws"),
				makeRecord(bootTime, ""),
			},
			want: "6.17.0-1010-aws",
		},
		{
			name: "no boot record at all returns empty",
			recs: [][]byte{
				makeRecord(7, "ssh"),
				makeRecord(8, ""),
			},
			want: "",
		},
		{
			name: "empty file returns empty",
			recs: [][]byte{},
			want: "",
		},
		{
			name: "file shorter than one record returns empty",
			recs: [][]byte{
				make([]byte, recordSizes[0]-1),
			},
			want: "",
		},
		{
			name: "trailing whitespace in ut_host is trimmed",
			recs: [][]byte{
				makeRecord(bootTime, "6.17.0-1010-aws  "),
			},
			want: "6.17.0-1010-aws",
		},
		{
			// Some wtmp files end with a partial record that doesn't
			// complete a full struct utmpx (observed on real Ubuntu 24.04
			// images). The parser must return the most recent BOOT_TIME
			// from the complete records and silently drop the trailing
			// fragment.
			name: "trailing partial record is ignored",
			recs: [][]byte{
				makeRecord(bootTime, "6.17.0-1010-aws"),
				make([]byte, 200), // half a record, dropped
			},
			want: "6.17.0-1010-aws",
		},
		{
			// Legacy 384-byte struct utmpx layout (32-bit timeval, classic
			// glibc on x86_64). The dual-size scan must fall back from 400
			// to 384 and find the BOOT_TIME record.
			name: "384-byte legacy layout parses via fallback",
			recs: [][]byte{
				makeRecordSize(bootTime, "5.15.0-92-generic", 384),
			},
			want: "5.15.0-92-generic",
		},
		{
			name: "384-byte layout: last BOOT_TIME wins",
			recs: [][]byte{
				makeRecordSize(bootTime, "5.15.0-89-generic", 384),
				makeRecordSize(bootTime, "5.15.0-92-generic", 384),
			},
			want: "5.15.0-92-generic",
		},
		{
			// Misaligned 400-byte read across a 384-only file must NOT
			// fake a BOOT_TIME record. Without the ut_user="reboot"
			// sanity check, a stray 0x0002 in record padding can
			// masquerade as ut_type=BOOT_TIME and return random ut_host
			// bytes.
			name: "BOOT_TIME without ut_user=reboot is rejected",
			recs: [][]byte{
				func() []byte {
					rec := make([]byte, recordSizes[0])
					binary.LittleEndian.PutUint16(rec[offType:], uint16(bootTime))
					// ut_user left empty — not a real systemd boot record.
					copy(rec[offHost:offHost+lenHost], "5.15.0-92-generic")
					return rec
				}(),
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			for _, r := range tt.recs {
				buf.Write(r)
			}
			got := Parse(bytes.NewReader(buf.Bytes()))
			if got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseStreaming verifies Parse handles a Reader that returns data
// in many small chunks (one record at a time) — the same kernel release
// must be detected as when the bytes are delivered in a single chunk.
func TestParseStreaming(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(makeRecord(bootTime, "5.15.0-89-generic"))
	buf.Write(makeRecord(7, "ssh-host"))
	buf.Write(makeRecord(bootTime, "5.15.0-92-generic"))

	// iotest.OneByteReader returns 1 byte per Read call, forcing the parser to
	// reassemble records across many chunked reads.
	got := Parse(iotest.OneByteReader(bytes.NewReader(buf.Bytes())))
	if got != "5.15.0-92-generic" {
		t.Errorf("Parse(one-byte) = %q, want %q", got, "5.15.0-92-generic")
	}
}

// TestParseLargeStream verifies the parser reads the whole file in
// constant memory and returns the LAST BOOT_TIME even when the file is
// large. wtmp is append-only, so the newest boot — the running kernel —
// lives at the tail; it must not be dropped in favor of an older record.
// The filler pushes the stream past 50 MB (the size of the former cap) to
// guard against reintroducing a truncating bound.
func TestParseLargeStream(t *testing.T) {
	const fillers = 70_000 // 70k * 400B ≈ 28 MB on each side, ~56 MB total

	var buf bytes.Buffer
	buf.Grow((2*fillers + 2) * recordSizes[0])
	writeFiller := func() {
		for range fillers {
			buf.Write(makeRecord(7, "ssh-host")) // USER_PROCESS
		}
	}
	writeFiller()
	buf.Write(makeRecord(bootTime, "5.15.0-89-generic")) // older boot, early
	writeFiller()
	buf.Write(makeRecord(bootTime, "6.17.0-1010-aws")) // newest boot, at the tail

	got := Parse(bytes.NewReader(buf.Bytes()))
	if got != "6.17.0-1010-aws" {
		t.Errorf("Parse(large) = %q, want %q", got, "6.17.0-1010-aws")
	}
}
