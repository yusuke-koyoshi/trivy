package walker

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
)

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
