package vm

import (
	"context"
	"errors"
	"time"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"

	"github.com/aquasecurity/trivy/pkg/log"
)

const opGetSnapshotBlock = "GetSnapshotBlock"

type ebsAPIStats struct {
	*apiStats
}

func newEBSAPIStats(logger *log.Logger) *ebsAPIStats {
	return &ebsAPIStats{newAPIStats(logger, "EBS", opGetSnapshotBlock)}
}

// apiOption runs after the Retry middleware, so it sees every attempt.
func (s *ebsAPIStats) apiOption(stack *middleware.Stack) error {
	return stack.Finalize.Insert(middleware.FinalizeMiddlewareFunc("TrivyEBSAPIStats",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
			sec := time.Now().Unix()
			out, md, err := next.HandleFinalize(ctx, in)
			// Use the codes the SDK retries as throttles, so that every throttle
			// absorbed by a retry is counted.
			throttled := false
			if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
				_, throttled = retry.DefaultThrottleErrorCodes[apiErr.ErrorCode()]
			}
			s.record(awsmiddleware.GetOperationName(ctx), sec, throttled)
			return out, md, err
		}), "Retry", middleware.After)
}
