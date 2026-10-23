package walker

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/masahiro331/go-disk/gpt"
	"github.com/masahiro331/go-disk/mbr"
	"github.com/masahiro331/go-disk/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/log"
)

type offsetRecorder struct {
	r       io.ReaderAt
	mu      sync.Mutex
	offsets []int64
}

func (o *offsetRecorder) ReadAt(p []byte, off int64) (int, error) {
	o.mu.Lock()
	o.offsets = append(o.offsets, off)
	o.mu.Unlock()
	return o.r.ReadAt(p, off)
}

func TestVM_WalkSectorSize(t *testing.T) {
	// An MBR disk with 4096-byte sectors whose only partition starts at LBA 1.
	disk := make([]byte, 64<<10)
	entry := disk[446:]
	entry[4] = 0x83
	binary.LittleEndian.PutUint32(entry[8:], 1)
	binary.LittleEndian.PutUint32(entry[12:], 8)
	disk[510], disk[511] = 0x55, 0xAA

	tests := []struct {
		name       string
		sectorSize int
		wantStart  int64
	}{
		{name: "fixed to 4096", sectorSize: 4096, wantStart: 4096},
		// MBR has no field for the sector size, so detection takes 512.
		{name: "detected", sectorSize: 0, wantStart: 512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &offsetRecorder{r: bytes.NewReader(disk)}
			sr := io.NewSectionReader(r, 0, int64(len(disk)))
			err := NewVM().Walk(sr, "/", Option{SectorSize: tt.sectorSize}, func(string, os.FileInfo, analyzer.Opener) error {
				return nil
			})
			require.NoError(t, err)
			assert.True(t, slices.Contains(r.offsets, tt.wantStart), "partition start not read, offsets: %v", r.offsets)
		})
	}
}

func TestDetectLVM(t *testing.T) {
	w := &VM{
		logger: log.WithPrefix("test"),
	}

	tests := []struct {
		name    string
		data    func() []byte
		want    bool
		wantErr bool
	}{
		{
			name: "LVM2 LABELONE at sector 0",
			data: func() []byte {
				buf := make([]byte, 2048)
				copy(buf[0:], "LABELONE")
				return buf
			},
			want: true,
		},
		{
			name: "LVM2 LABELONE at sector 1 (default pvcreate)",
			data: func() []byte {
				buf := make([]byte, 2048)
				copy(buf[512:], "LABELONE")
				return buf
			},
			want: true,
		},
		{
			name: "LVM2 LABELONE at sector 2",
			data: func() []byte {
				buf := make([]byte, 2048)
				copy(buf[1024:], "LABELONE")
				return buf
			},
			want: true,
		},
		{
			name: "LVM2 LABELONE at sector 3",
			data: func() []byte {
				buf := make([]byte, 2048)
				copy(buf[1536:], "LABELONE")
				return buf
			},
			want: true,
		},
		{
			name: "LVM1 HM at sector 0",
			data: func() []byte {
				buf := make([]byte, 2048)
				copy(buf[0:], "HM")
				return buf
			},
			want: true,
		},
		{
			name: "no LVM signature",
			data: func() []byte {
				return make([]byte, 2048)
			},
			want: false,
		},
		{
			name: "data shorter than 4 sectors",
			data: func() []byte {
				return make([]byte, 4)
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.data()
			r := bytes.NewReader(data)
			sr := io.NewSectionReader(r, 0, int64(len(data)))
			got, err := w.detectLVM(*sr)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestShouldSkip(t *testing.T) {
	// EFI System Partition GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
	// Stored in mixed-endian format as per GPT spec
	efiGUID := gpt.GUID{
		0x28, 0x73, 0x2A, 0xC1, // C12A7328 (little-endian)
		0x1F, 0xF8, // F81F (little-endian)
		0xD2, 0x11, // 11D2 (little-endian)
		0xBA, 0x4B, // BA4B (big-endian)
		0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B, // 00A0C93EC93B (big-endian)
	}

	tests := []struct {
		name string
		part types.Partition
		want bool
	}{
		{
			name: "empty MBR partition is skipped",
			part: &mbr.Partition{Type: 0x00},
			want: true,
		},
		{
			name: "GPT partition with zero GUID is not caught by empty check",
			part: &gpt.PartitionEntry{},
			want: false, // GetType() returns 16-byte zero GUID, not []byte{0x00}
		},
		{
			name: "MBR partition with any name is not skipped",
			part: &mbr.Partition{Type: 0x83},
			want: false,
		},
		{
			name: "GPT boot partition (EFI) is skipped",
			part: &gpt.PartitionEntry{
				PartitionTypeGUID: efiGUID,
			},
			want: true,
		},
		{
			name: "GPT non-boot partition is not skipped",
			part: &gpt.PartitionEntry{
				PartitionTypeGUID: gpt.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
			},
			want: false,
		},
		{
			name: "MBR swap partition is skipped",
			part: &mbr.Partition{Type: 0x82},
			want: true,
		},
		{
			name: "MBR extended partition (CHS) is skipped",
			part: &mbr.Partition{Type: 0x05},
			want: true,
		},
		{
			name: "MBR extended partition (LBA) is skipped",
			part: &mbr.Partition{Type: 0x0F},
			want: true,
		},
		{
			name: "MBR extended partition (Linux) is skipped",
			part: &mbr.Partition{Type: 0x85},
			want: true,
		},
		{
			name: "GPT swap partition is skipped",
			part: &gpt.PartitionEntry{
				PartitionTypeGUID: linuxSwapGUID,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldSkip(tt.part)
			assert.Equal(t, tt.want, got)
		})
	}
}
