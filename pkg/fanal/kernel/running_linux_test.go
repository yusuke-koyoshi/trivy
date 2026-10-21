//go:build linux

package kernel

import (
	"os"
	"testing"
)

func TestRunning(t *testing.T) {
	// On Linux, /proc/sys/kernel/osrelease is always present and non-empty
	// when running under a real kernel (which test environments are).
	got, err := Running()
	if err != nil {
		// Some sandboxed environments (gVisor, certain CI containers) may
		// hide /proc; treat it as a soft-fail with skip rather than a failure.
		if os.IsNotExist(err) {
			t.Skip("/proc/sys/kernel/osrelease not available")
		}
		t.Fatalf("Running() returned error: %v", err)
	}
	if got == "" {
		t.Fatal("Running() returned empty release string")
	}
	// Must not contain whitespace; TrimSpace should have removed any.
	for _, c := range got {
		if c == '\n' || c == '\r' || c == '\t' || c == ' ' {
			t.Fatalf("Running() returned %q which contains whitespace", got)
		}
	}
}
