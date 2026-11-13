// Package cloud finds AI agents in AWS and Azure from a local configuration
// (.env) and quarantines an AWS agent through IAM.
//
// Secret values (access keys, client secrets, tokens) never reach Config,
// Agent, Plan, warnings or errors: Config says only whether a secret is set,
// and the SDK or token call reads it from the process environment. Agent
// instructions, prompts, metadata and environment variable values returned
// by the clouds are never decoded.
package cloud

import (
	"net/http"
	"strings"
	"time"
)

// Config is what --cloud mode reads from .env.
type Config struct {
	Clouds []string // "aws", "azure"
	AWS    AWS
	Azure  Azure
}

// AWS selects the credentials and regions to read.
type AWS struct {
	Profile string
	Regions []string
}

// Azure selects the tenant, subscriptions and credentials to read.
type Azure struct {
	TenantID        string
	SubscriptionIDs []string
	ClientID        string
	// ClientSecretSet is whether AZURE_CLIENT_SECRET is set; the value is read
	// from the environment only when a token is requested.
	ClientSecretSet bool
}

// Warning is advice about the configuration. It never holds a value.
type Warning string

// Agent kinds.
const (
	kindBedrockAgent     = "bedrock-agent"
	kindAgentCoreRuntime = "agentcore-runtime"
	kindAzureDeployment  = "azure-openai-deployment"
	kindFoundryAgent     = "azure-foundry-agent"
)

// Agent is one AI agent found in a cloud account.
type Agent struct {
	Cloud    string    `json:"cloud"` // aws | azure
	Kind     string    `json:"kind"`
	ID       string    `json:"id"` // ARN, ARM id, or ARM project id + "/assistants/" + agent id
	Name     string    `json:"name"`
	Region   string    `json:"region,omitempty"`
	Account  string    `json:"account,omitempty"`  // AWS account id or Azure subscription id
	Identity string    `json:"identity,omitempty"` // execution role ARN or managed identity principal id
	Model    string    `json:"model,omitempty"`
	Status   string    `json:"status,omitempty"`
	Updated  time.Time `json:"updated,omitempty"`
	Console  string    `json:"console,omitempty"` // console URL
	Evidence []string  `json:"evidence,omitempty"`
}

// Test seams: every cloud call goes through these.
var (
	// httpClient carries every AWS and Azure request.
	httpClient = &http.Client{Timeout: 30 * time.Second}
	// awsEndpoint, when set, replaces every AWS service endpoint.
	awsEndpoint = ""
	// armBase is Azure Resource Manager.
	armBase = "https://management.azure.com"
	// loginBase is the Microsoft identity platform.
	loginBase = "https://login.microsoftonline.com"
	// foundryBase is the data-plane host of a Foundry (AIServices) account.
	foundryBase = func(subdomain string) string { return "https://" + subdomain + ".services.ai.azure.com" }
)

// splitList splits a comma list, trimming spaces and dropping empty and
// repeated entries.
func splitList(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// lastSegment returns what follows the last "/" of an id.
func lastSegment(id string) string {
	return id[strings.LastIndex(id, "/")+1:]
}
