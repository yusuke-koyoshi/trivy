package banner

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "dmesg single banner",
			input: "[    0.000000] Linux version 6.1.158-178.288.amzn2023.aarch64 (mockbuild@build) (gcc) #1 SMP\n[    0.000001] Command line: ...\n",
			want:  "6.1.158-178.288.amzn2023.aarch64",
		},
		{
			name: "kern.log with syslog prefix and multiple boots",
			input: strings.Join([]string{
				"Apr 25 10:00:00 host kernel: [    0.000000] Linux version 5.15.0-90-generic (build@h) (gcc) #100",
				"Apr 25 10:00:01 host kernel: ... boot 1 messages ...",
				"Apr 26 12:34:56 host kernel: [    0.000000] Linux version 5.15.0-92-generic (build@h) (gcc) #102",
				"Apr 26 12:34:57 host kernel: ... boot 2 messages ...",
				"",
			}, "\n"),
			want: "5.15.0-92-generic",
		},
		{
			name:  "messages with kernel banner mixed in syslog",
			input: "Mar  1 00:00:00 host systemd[1]: Started thing.\nMar  1 00:00:01 host kernel: [    0.000000] Linux version 4.18.0-553.el8_10.x86_64 (mockbuild) (gcc)\n",
			want:  "4.18.0-553.el8_10.x86_64",
		},
		{
			name:  "no banner present",
			input: "Mar  1 00:00:00 host systemd[1]: Started thing.\nMar  1 00:00:01 host sshd[123]: Accepted ...\n",
			want:  "",
		},
		{
			// Modern Ubuntu rsyslog/journald strips the [N.N] kernel timestamp
			// before forwarding kernel messages to /var/log/kern.log, leaving
			// only the `kernel:` syslog facility marker.
			name:  "Ubuntu 24.04 syslog format without kernel timestamp",
			input: "2026-04-28T14:45:03.080181+00:00 ip-172-31-15-15 kernel: Linux version 6.17.0-1012-aws (buildd@bos03-arm64-008) (aarch64-linux-gnu-gcc-13) #12~24.04.1-Ubuntu SMP\n",
			want:  "6.17.0-1012-aws",
		},
		{
			// Regression: user-space log lines that mention "Linux version X"
			// (apt install output, update-grub, etc.) must NOT match. The
			// kernel-facility marker is required so we only pick up genuine
			// boot-time kernel banners.
			name: "userspace mention of Linux version is rejected",
			input: strings.Join([]string{
				// Real boot banner of 1010 (current running)
				"2026-04-28T10:00:00 host kernel: Linux version 6.17.0-1010-aws (buildd) (gcc) #1010-Ubuntu",
				// apt install logs a userspace message — must NOT win over banner
				"2026-04-28T15:00:00 host apt[123]: Setting up linux-image-6.17.0-1012-aws ... Linux version 6.17.0-1012-aws will be installed",
				"",
			}, "\n"),
			want: "6.17.0-1010-aws",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(strings.NewReader(tt.input))
			if got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}
