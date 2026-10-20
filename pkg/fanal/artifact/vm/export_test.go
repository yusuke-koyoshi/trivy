package vm

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/aquasecurity/trivy/pkg/log"
)

// SetAzureClient points an Azure artifact at fakes instead of Azure, and
// sends its API usage logs to logger.
func SetAzureClient(a *Azure, cred azcore.TokenCredential, transport policy.Transporter, logger *log.Logger) {
	a.cred = cred
	a.options.Transport = transport
	a.stats = newAzureAPIStats(logger)
	a.options.PerRetryPolicies = []policy.Policy{a.stats}
}
