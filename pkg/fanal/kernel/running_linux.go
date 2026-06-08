//go:build linux

package kernel

import (
	"os"
	"strings"
)

// Running returns the running kernel release (`uname -r`) from
// /proc/sys/kernel/osrelease.
//
// This is always the host running the trivy process, not necessarily the
// scan target. Callers must cross-match against detected kernel package
// releases to confirm the target is the live host.
func Running() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
