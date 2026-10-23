package walker

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

const defaultSizeThreshold = int64(100) << 20 // 100MB

var defaultSkipDirs = []string{
	"**/.git",
	"proc",
	"sys",
	"dev",
}

type Option struct {
	SkipFiles []string
	SkipDirs  []string

	// SectorSize is the logical sector size of a VM disk, 512 or 4096. Zero
	// detects it, which works only for GPT disks.
	SectorSize int
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error
