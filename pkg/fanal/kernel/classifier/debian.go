package classifier

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// debianKernelPrefixes lists known binary-package prefixes whose suffix is
// the kernel release string when the package is a concrete kernel binary
// (not a meta package). Order matters: longer prefixes must come first so
// that strings.HasPrefix matches the most specific name. The set follows
// the Debian/Ubuntu binary kernel package naming convention.
var debianKernelPrefixes = []string{
	"linux-image-unsigned-",
	"linux-signed-image-",
	"linux-modules-extra-",
	"linux-cloud-tools-",
	"linux-buildinfo-",
	"linux-image-uc-",
	"linux-image-",
	"linux-headers-",
	"linux-modules-",
	"linux-tools-",
	"linux-lib-rust-",
}

func classifyDebian(pkg types.Package) Result {
	for _, prefix := range debianKernelPrefixes {
		if !strings.HasPrefix(pkg.Name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(pkg.Name, prefix)
		// Concrete kernel binaries have a release suffix that begins with a
		// digit (e.g. "5.15.0-92-generic"). Meta packages such as
		// "linux-image-generic" or "linux-image-amd64" begin with a letter
		// and must be excluded.
		if rel == "" || rel[0] < '0' || rel[0] > '9' {
			return Result{}
		}
		return Result{IsKernel: true, Release: rel}
	}
	return Result{}
}
