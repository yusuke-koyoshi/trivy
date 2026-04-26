//go:build linux

package kernel

import (
	"os"
	"strings"
)

// Running returns the release string of the currently running kernel
// (equivalent to `uname -r`) by reading /proc/sys/kernel/osrelease.
//
// This always returns the kernel of the host running the trivy process,
// not necessarily the kernel of the scan target. Callers must validate
// by cross-matching against detected kernel package release strings to
// confirm the target is the live host.
func Running() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
