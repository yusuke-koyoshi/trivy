package vm

import (
	"maps"
	"slices"
	"sync"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/log"
)

// apiStats counts every attempt of the cloud API calls a scan makes, including
// the ones the SDK retries. Throttles absorbed by the SDK retries never reach
// Trivy as errors, so this is the only place they become visible.
type apiStats struct {
	logger *log.Logger
	// service names the API in the log messages, such as "EBS".
	service string
	// rateOp is the operation that reads the disk blocks. Its attempts per
	// second are what a throttling limit applies to.
	rateOp string

	mu        sync.Mutex
	attempts  map[string]int64
	throttles map[string]int64
	// rateOp attempts by the Unix second they started in. Attempts finish out
	// of order, so a single running counter would undercount.
	perSec    map[int64]int64
	maxPerSec int64
}

func newAPIStats(logger *log.Logger, service, rateOp string) *apiStats {
	return &apiStats{
		logger:    logger,
		service:   service,
		rateOp:    rateOp,
		attempts:  make(map[string]int64),
		throttles: make(map[string]int64),
		perSec:    make(map[int64]int64),
	}
}

// record counts an attempt and warns on the first throttle of each operation.
func (s *apiStats) record(op string, sec int64, throttled bool) {
	s.mu.Lock()
	s.attempts[op]++
	if op == s.rateOp {
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
		s.logger.Warn(s.service+" API request throttled", log.String("operation", op))
	}
}

// logSummary logs the counts once per scan. It logs nothing without attempts.
func (s *apiStats) logSummary() {
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
		if op == s.rateOp {
			attrs = append(attrs, log.Int64(key+"_max_attempts_per_second", s.maxPerSec))
		}
	}
	s.logger.Info(s.service+" API usage", attrs...)
}
