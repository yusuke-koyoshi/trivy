//go:build !linux

package kernel

import "errors"

// Running is a stub for non-Linux platforms; it always returns an error.
func Running() (string, error) {
	return "", errors.New("running kernel detection is not supported on this platform")
}
