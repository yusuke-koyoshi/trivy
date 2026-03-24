package walker

import (
	"testing"

	"github.com/masahiro331/go-disk/gpt"
	"github.com/masahiro331/go-disk/mbr"
	"github.com/masahiro331/go-disk/types"
	"github.com/stretchr/testify/assert"
)

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
