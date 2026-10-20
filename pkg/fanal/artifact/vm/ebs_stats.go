package vm

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/log"
)

const opGetSnapshotBlock = "GetSnapshotBlock"

// ebsAPIStats counts every attempt of the EBS direct API calls, including
// the ones the SDK retries. Throttles absorbed by the SDK retries never
// reach Trivy as errors, so this is the only place they become visible.
type ebsAPIStats struct {
	logger *log.Logger

	mu        sync.Mutex
	attempts  map[string]int64
	throttles map[string]int64
	// GetSnapshotBlock attempts by the Unix second they started in. Attempts
	// finish out of order, so a single running counter would undercount.
	perSec    map[int64]int64
	maxPerSec int64
}

func newEBSAPIStats(logger *log.Logger) *ebsAPIStats {
	return &ebsAPIStats{
		logger:    logger,
		attempts:  make(map[string]int64),
		throttles: make(map[string]int64),
		perSec:    make(map[int64]int64),
	}
}

// apiOption runs after the Retry middleware, so it sees every attempt.
func (s *ebsAPIStats) apiOption(stack *middleware.Stack) error {
	return stack.Finalize.Insert(middleware.FinalizeMiddlewareFunc("TrivyEBSAPIStats",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
			sec := time.Now().Unix()
			out, md, err := next.HandleFinalize(ctx, in)
			// Use the codes the SDK retries as throttles, so that every throttle
			// absorbed by a retry is counted.
			var apiErr smithy.APIError
			throttled := false
			if errors.As(err, &apiErr) {
				_, throttled = retry.DefaultThrottleErrorCodes[apiErr.ErrorCode()]
			}
			s.record(awsmiddleware.GetOperationName(ctx), sec, throttled)
			return out, md, err
		}), "Retry", middleware.After)
}

// record counts an attempt and warns on the first throttle of each operation.
func (s *ebsAPIStats) record(op string, sec int64, throttled bool) {
	s.mu.Lock()
	s.attempts[op]++
	if op == opGetSnapshotBlock {
		s.perSec[sec]++
		s.maxPerSec = max(s.maxPerSec, s.perSec[sec])
	}
	var firstThrottle bool
	if throttled {
		s.throttles[op]++
		firstThrottle = s.throttles[op] == 1
	}
	s.mu.Unlock()

	if firstThrottle {
		s.logger.Warn("EBS API request throttled", log.String("operation", op))
	}
}

// logSummary logs the counts once per scan. It logs nothing without attempts.
func (s *ebsAPIStats) logSummary() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.attempts) == 0 {
		return
	}

	var attrs []any
	for _, op := range slices.Sorted(maps.Keys(s.attempts)) {
		key := lo.SnakeCase(op)
		attrs = append(attrs,
			log.Int64(key+"_attempts", s.attempts[op]),
			log.Int64(key+"_throttles", s.throttles[op]),
		)
		if op == opGetSnapshotBlock {
			attrs = append(attrs, log.Int64(key+"_max_attempts_per_second", s.maxPerSec))
		}
	}
	s.logger.Info("EBS API usage", attrs...)
}
