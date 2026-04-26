//go:build !linux

package kernel

import "errors"

// ErrUnsupported is returned by Running on platforms that do not provide
// /proc/sys/kernel/osrelease.
var ErrUnsupported = errors.New("running kernel detection is not supported on this platform")

// Running is a stub for non-Linux platforms; it always returns ErrUnsupported.
func Running() (string, error) {
	return "", ErrUnsupported
}
