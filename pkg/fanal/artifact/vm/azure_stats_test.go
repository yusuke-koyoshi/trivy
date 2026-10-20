package vm

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/log"
)

func TestAzureAPIStats_Do(t *testing.T) {
	tests := []struct {
		name             string
		method           string
		apiName          string // the API name the ARM clients put in the context
		failures         int64  // number of leading requests the server fails
		failStatus       int
		failCode         string
		wantOp           string
		wantAttempts     int64
		wantThrottles    int64
		wantServerErrors int64
		wantWarning      string
		wantErr          bool
	}{
		{
			name:         "no throttle",
			method:       http.MethodGet,
			wantOp:       opGetBlob,
			wantAttempts: 1,
		},
		{
			name:          "blob throttled and then retried successfully",
			method:        http.MethodGet,
			failures:      2,
			failStatus:    http.StatusServiceUnavailable,
			failCode:      "ServerBusy",
			wantOp:        opGetBlob,
			wantAttempts:  3,
			wantThrottles: 2,
			wantWarning:   "Azure API request throttled\toperation=\"GetBlob\" status=503 error_code=\"ServerBusy\"\n",
		},
		{
			name:          "ARM throttled and then retried successfully",
			method:        http.MethodPost,
			apiName:       "SnapshotsClient.BeginGrantAccess",
			failures:      1,
			failStatus:    http.StatusTooManyRequests,
			wantOp:        "GrantAccess",
			wantAttempts:  2,
			wantThrottles: 1,
			wantWarning:   "Azure API request throttled\toperation=\"GrantAccess\" status=429\n",
		},
		{
			name:             "server error counted apart from throttles",
			method:           http.MethodHead,
			failures:         1,
			failStatus:       http.StatusInternalServerError,
			failCode:         "OperationTimedOut",
			wantOp:           opGetBlobProperties,
			wantAttempts:     2,
			wantServerErrors: 1,
			wantWarning:      "Azure API server error\toperation=\"GetBlobProperties\" status=500 error_code=\"OperationTimedOut\"\n",
		},
		{
			name:             "503 without ServerBusy is an outage, not a throttle",
			method:           http.MethodGet,
			apiName:          "SnapshotsClient.Get",
			failures:         1,
			failStatus:       http.StatusServiceUnavailable,
			wantOp:           "GetSnapshot",
			wantAttempts:     2,
			wantServerErrors: 1,
			wantWarning:      "Azure API server error\toperation=\"GetSnapshot\" status=503\n",
		},
		{
			name:          "throttled on every attempt",
			method:        http.MethodGet,
			failures:      100,
			failStatus:    http.StatusServiceUnavailable,
			failCode:      "ServerBusy",
			wantOp:        opGetBlob,
			wantAttempts:  3,
			wantThrottles: 3,
			wantWarning:   "Azure API request throttled",
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) <= tt.failures {
					if tt.failCode != "" {
						w.Header().Set("x-ms-error-code", tt.failCode)
					}
					w.WriteHeader(tt.failStatus)
				}
			}))
			defer server.Close()

			var buf bytes.Buffer
			stats := newAzureAPIStats(log.New(log.NewHandler(&buf, nil)))
			pl := runtime.NewPipeline("trivy-test", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{
				Retry: policy.RetryOptions{
					MaxRetries:    2,
					RetryDelay:    time.Nanosecond,
					MaxRetryDelay: time.Nanosecond,
				},
				PerRetryPolicies: []policy.Policy{stats},
			})

			ctx := t.Context()
			if tt.apiName != "" {
				ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, tt.apiName)
			}
			req, err := runtime.NewRequest(ctx, tt.method, server.URL+"/disk?sig=x")
			require.NoError(t, err)
			resp, err := pl.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			if tt.wantErr {
				assert.Equal(t, tt.failStatus, resp.StatusCode)
			} else {
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}

			assert.Equal(t, tt.wantAttempts, stats.attempts[tt.wantOp])
			assert.Equal(t, tt.wantThrottles, stats.throttles[tt.wantOp])
			assert.Equal(t, tt.wantServerErrors, stats.serverErrors[tt.wantOp])
			if tt.wantWarning == "" {
				assert.NotContains(t, buf.String(), "WARN")
			} else {
				assert.Equal(t, 1, strings.Count(buf.String(), "WARN"), "one warning per operation")
				assert.Contains(t, buf.String(), tt.wantWarning)
			}
		})
	}
}

func TestAzureOperationName(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		url     string
		apiName string
		want    string
	}{
		{
			name:    "grant",
			method:  http.MethodPost,
			url:     "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/snapshots/snap/beginGetAccess?api-version=2026-03-02",
			apiName: "SnapshotsClient.BeginGrantAccess",
			want:    "GrantAccess",
		},
		{
			name:    "revocation",
			method:  http.MethodPost,
			url:     "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/snapshots/snap/endGetAccess?api-version=2026-03-02",
			apiName: "SnapshotsClient.BeginRevokeAccess",
			want:    "RevokeAccess",
		},
		{
			name:    "snapshot lookup",
			method:  http.MethodGet,
			url:     "https://management.azure.com/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/snapshots/snap?api-version=2026-03-02",
			apiName: "SnapshotsClient.Get",
			want:    "GetSnapshot",
		},
		{
			name:   "polling",
			method: http.MethodGet,
			url:    "https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/locations/japaneast/DiskOperations/op?api-version=2026-03-02",
			want:   opPollOperation,
		},
		{
			name:   "blob properties",
			method: http.MethodHead,
			url:    "https://md-x.z1.blob.storage.azure.net/x/abcd?sv=2018-03-28&sig=x",
			want:   opGetBlobProperties,
		},
		{
			name:   "page ranges",
			method: http.MethodGet,
			url:    "https://md-x.z1.blob.storage.azure.net/x/abcd?comp=pagelist&sv=2018-03-28&sig=x",
			want:   opGetPageRanges,
		},
		{
			name:   "range read",
			method: http.MethodGet,
			url:    "https://md-x.z1.blob.storage.azure.net/x/abcd?sv=2018-03-28&sig=x",
			want:   opGetBlob,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			if tt.apiName != "" {
				ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, tt.apiName)
			}
			req, err := http.NewRequestWithContext(ctx, tt.method, tt.url, http.NoBody)
			require.NoError(t, err)
			assert.Equal(t, tt.want, azureOperationName(req))
		})
	}
}

func TestAzureAPIStats_logSummary(t *testing.T) {
	var buf bytes.Buffer
	stats := newAzureAPIStats(log.New(log.NewHandler(&buf, nil)))
	stats.record(opGetBlob, 1, false)
	stats.record(opGetBlob, 1, true)
	stats.record("GrantAccess", 1, false)
	stats.recordServerError("GrantAccess")
	buf.Reset()

	stats.logSummary()

	got := buf.String()
	assert.Contains(t, got, "Azure API usage")
	assert.Contains(t, got, "get_blob_attempts=2 get_blob_throttles=1 get_blob_server_errors=0 get_blob_max_attempts_per_second=2 grant_access_attempts=1 grant_access_throttles=0 grant_access_server_errors=1")
}
