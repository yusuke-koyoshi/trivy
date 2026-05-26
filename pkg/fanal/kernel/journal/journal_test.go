package journal

import (
	"bytes"
	"testing"
)

func TestParse(t *testing.T) {
	// Build a synthetic journal-like blob with realistic structure:
	// some binary noise, an uncompressed banner Data object payload,
	// and trailing object alignment bytes (NUL).
	mkBlob := func(banners ...string) []byte {
		var buf bytes.Buffer
		buf.WriteString("LPKSHHRH") // file signature
		buf.Write(make([]byte, 248)) // padding to typical header size
		for _, b := range banners {
			// Object header (16 bytes of varied non-printable data) +
			// payload + NUL alignment.
			buf.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			buf.Write([]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			buf.WriteString(b)
			buf.Write([]byte{0x00, 0x00, 0x00})
		}
		return buf.Bytes()
	}

	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name: "single banner: typical AL2023 kernel banner payload",
			input: mkBlob(
				"MESSAGE=Linux version 6.1.141-167.250.amzn2023.aarch64 (mockbuild@buildhost) (gcc 11.4.0)",
			),
			want: "6.1.141-167.250.amzn2023.aarch64",
		},
		{
			name: "multiple boots: most recent (last in file) wins",
			input: mkBlob(
				"MESSAGE=Linux version 5.15.0-89-generic (build@h) (gcc 11)",
				"MESSAGE=Linux version 5.15.0-92-generic (build@h) (gcc 11)",
				"MESSAGE=Linux version 6.1.141-167.250.amzn2023.aarch64 (mockbuild@build) (gcc)",
			),
			want: "6.1.141-167.250.amzn2023.aarch64",
		},
		{
			name: "Debian/Ubuntu format banner",
			input: mkBlob(
				"MESSAGE=Linux version 5.15.0-92-generic (buildd@lcy02) (gcc 11.4.0) #102-Ubuntu SMP",
			),
			want: "5.15.0-92-generic",
		},
		{
			name:  "no banner present",
			input: mkBlob("MESSAGE=systemd-resolved started", "MESSAGE=foo bar"),
			want:  "",
		},
		{
			name:  "empty input",
			input: []byte{},
			want:  "",
		},
		{
			name: "release token ends at space (not at NUL when banner has trailing text)",
			input: mkBlob(
				"MESSAGE=Linux version 6.1.0-13-cloud-amd64 (debian-kernel@lists.debian.org)",
			),
			want: "6.1.0-13-cloud-amd64",
		},
		{
			// Regression: a userspace log entry mentioning a kernel version
			// without the kernel banner's `(buildhost)` suffix must NOT win
			// over the real boot banner. apt install, update-grub, dpkg
			// triggers etc. typically write something like "Linux version
			// X.Y.Z-flavor will be installed" or "linux-image-X-Y-flavor
			// configured for kernel Linux version X.Y.Z" — these lack the
			// open-paren immediately after the release token.
			name: "userspace mention of Linux version is rejected",
			input: mkBlob(
				// Real boot banner of 1010 (current running kernel)
				"MESSAGE=Linux version 6.17.0-1010-aws (buildd@host) (gcc 13.3.0)",
				// Userspace log entry (no `(...)` after release) — must NOT win
				"MESSAGE=Linux version 6.17.0-1012-aws will be installed soon",
			),
			want: "6.17.0-1010-aws",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(bytes.NewReader(tt.input))
			if got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseChunkBoundary covers the streaming reader's overlap window:
// a banner that straddles the boundary between two 1 MB read chunks
// must still be detected.
func TestParseChunkBoundary(t *testing.T) {
	const wantRelease = "6.17.0-1010-aws"
	bannerLine := "MESSAGE=Linux version " + wantRelease + " (build@host) (gcc 13)"

	// Place the banner so that its midpoint lands exactly on the chunk
	// boundary. The first chunk ends at offset chunkSize; we start the
	// banner ~half its length before that.
	pre := chunkSize - len(bannerLine)/2
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte{0x00}, pre))
	buf.WriteString(bannerLine)
	// Append more padding so the second chunk has content too.
	buf.Write(bytes.Repeat([]byte{0x00}, chunkSize/2))

	got := Parse(bytes.NewReader(buf.Bytes()))
	if got != wantRelease {
		t.Errorf("Parse(boundary) = %q, want %q", got, wantRelease)
	}
}
