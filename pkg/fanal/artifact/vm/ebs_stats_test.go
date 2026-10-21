package vm

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/smithy-go/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
)

const throttledWarning = "EBS API request throttled"

func TestEBSAPIStats_apiOption(t *testing.T) {
	tests := []struct {
		name          string
		throttles     int64 // number of leading requests the server throttles
		call          func(t *testing.T, client *ebs.Client) error
		wantOp        string
		wantAttempts  int64
		wantThrottles int64
		wantWarnings  int
		wantErr       bool
	}{
		{
			name:          "no throttle",
			throttles:     0,
			call:          listSnapshotBlocks,
			wantOp:        "ListSnapshotBlocks",
			wantAttempts:  1,
			wantThrottles: 0,
			wantWarnings:  0,
		},
		{
			name:          "throttled and then retried successfully",
			throttles:     2,
			call:          listSnapshotBlocks,
			wantOp:        "ListSnapshotBlocks",
			wantAttempts:  3,
			wantThrottles: 2,
			wantWarnings:  1,
		},
		{
			name:          "throttled on every attempt",
			throttles:     100,
			call:          getSnapshotBlock,
			wantOp:        opGetSnapshotBlock,
			wantAttempts:  3,
			wantThrottles: 3,
			wantWarnings:  1,
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if requests.Add(1) <= tt.throttles {
					w.Header().Set("X-Amzn-ErrorType", "RequestThrottledException")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"message":"Rate exceeded"}`))
					return
				}
				_, _ = w.Write([]byte(`{"BlockSize":524288,"Blocks":[]}`))
			}))
			defer server.Close()

			var buf bytes.Buffer
			stats := newEBSAPIStats(log.New(log.NewHandler(&buf, nil)))
			client := ebs.New(ebs.Options{
				Region:       "us-east-1",
				BaseEndpoint: aws.String(server.URL),
				Credentials:  aws.AnonymousCredentials{},
				Retryer: retry.NewStandard(func(o *retry.StandardOptions) {
					o.MaxAttempts = 3
					o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
					o.RateLimiter = ratelimit.None
				}),
				APIOptions: []func(*middleware.Stack) error{stats.apiOption},
			})

			err := tt.call(t, client)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantAttempts, stats.attempts[tt.wantOp])
			assert.Equal(t, tt.wantThrottles, stats.throttles[tt.wantOp])
			assert.Equal(t, tt.wantWarnings, strings.Count(buf.String(), throttledWarning))
		})
	}
}

func listSnapshotBlocks(t *testing.T, client *ebs.Client) error {
	_, err := client.ListSnapshotBlocks(t.Context(), &ebs.ListSnapshotBlocksInput{
		SnapshotId: aws.String("snap-012345"),
	})
	return err
}

func getSnapshotBlock(t *testing.T, client *ebs.Client) error {
	_, err := client.GetSnapshotBlock(t.Context(), &ebs.GetSnapshotBlockInput{
		SnapshotId: aws.String("snap-012345"),
		BlockIndex: aws.Int32(0),
		BlockToken: aws.String("token"),
	})
	return err
}

func TestEBSAPIStats_record(t *testing.T) {
	var buf bytes.Buffer
	stats := newEBSAPIStats(log.New(log.NewHandler(&buf, nil)))

	// An attempt started in second 10 finishes after attempts started in
	// second 11, which must not reset the count of second 11.
	stats.record(opGetSnapshotBlock, 11, false)
	stats.record(opGetSnapshotBlock, 11, false)
	stats.record(opGetSnapshotBlock, 10, false)
	stats.record(opGetSnapshotBlock, 11, true)
	stats.record(opGetSnapshotBlock, 12, true)
	stats.record("ListSnapshotBlocks", 12, true)

	assert.Equal(t, int64(5), stats.attempts[opGetSnapshotBlock])
	assert.Equal(t, int64(2), stats.throttles[opGetSnapshotBlock])
	assert.Equal(t, int64(3), stats.maxPerSec)
	assert.Equal(t, int64(1), stats.attempts["ListSnapshotBlocks"])
	assert.Equal(t, 2, strings.Count(buf.String(), throttledWarning), "one warning per operation")
}

func TestEBSAPIStats_logSummary(t *testing.T) {
	t.Run("with attempts", func(t *testing.T) {
		var buf bytes.Buffer
		stats := newEBSAPIStats(log.New(log.NewHandler(&buf, nil)))
		stats.record(opGetSnapshotBlock, 1, false)
		stats.record(opGetSnapshotBlock, 1, true)
		stats.record("ListSnapshotBlocks", 1, false)
		buf.Reset()

		stats.logSummary()

		got := buf.String()
		assert.Contains(t, got, "EBS API usage")
		assert.Contains(t, got, "get_snapshot_block_attempts=2 get_snapshot_block_throttles=1 get_snapshot_block_max_attempts_per_second=2 list_snapshot_blocks_attempts=1 list_snapshot_blocks_throttles=0")
	})

	t.Run("without attempts", func(t *testing.T) {
		var buf bytes.Buffer
		stats := newEBSAPIStats(log.New(log.NewHandler(&buf, nil)))

		stats.logSummary()

		assert.Empty(t, buf.String())
	})
}
