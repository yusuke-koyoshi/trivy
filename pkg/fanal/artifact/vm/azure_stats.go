package vm

import (
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	opGetBlob           = "GetBlob"
	opGetBlobProperties = "GetBlobProperties"
	opGetPageRanges     = "GetPageRanges"
	// opPollOperation is the ARM polling of a grant or a revocation, which
	// carries no API name.
	opPollOperation = "PollOperation"
)

// azureAPIStats counts the attempts of the ARM and blob requests of a scan.
// It is passed as a per-retry policy, so it sees every attempt.
type azureAPIStats struct {
	*apiStats
}

func newAzureAPIStats(logger *log.Logger) *azureAPIStats {
	s := newAPIStats(logger, "Azure", opGetBlob)
	s.reportServerErrors = true
	return &azureAPIStats{s}
}

func (s *azureAPIStats) Do(req *policy.Request) (*http.Response, error) {
	sec := time.Now().Unix()
	resp, err := req.Next()
	op := azureOperationName(req.Raw())
	if resp == nil {
		s.record(op, sec, false)
		return resp, err
	}

	code := resp.Header.Get("x-ms-error-code")
	attrs := []any{log.Int("status", resp.StatusCode)}
	if code != "" {
		attrs = append(attrs, log.String("error_code", code))
	}
	// Only the responses that say a limit was hit, so that an outage is not
	// taken for throttling: 429 from ARM and ServerBusy from blob storage.
	throttled := resp.StatusCode == http.StatusTooManyRequests || code == "ServerBusy"
	s.record(op, sec, throttled, attrs...)
	if !throttled && resp.StatusCode >= http.StatusInternalServerError {
		s.recordServerError(op, attrs...)
	}
	return resp, err
}

// azureOperationName falls back to the method and query for the blob
// requests, which carry no API name.
func azureOperationName(req *http.Request) string {
	if name, ok := req.Context().Value(runtime.CtxAPINameKey{}).(string); ok {
		// For example, "SnapshotsClient.BeginGrantAccess" becomes "GrantAccess".
		name = strings.TrimPrefix(name[strings.LastIndex(name, ".")+1:], "Begin")
		if name == "Get" {
			return "GetSnapshot"
		}
		return name
	}
	query := req.URL.Query()
	switch {
	case query.Has("api-version"):
		return opPollOperation
	case req.Method == http.MethodHead:
		return opGetBlobProperties
	case query.Get("comp") == "pagelist":
		return opGetPageRanges
	default:
		return opGetBlob
	}
}
