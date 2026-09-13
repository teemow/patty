// Package grafana is the Grafana credential provider: service account
// tokens, Grafana Cloud access policy tokens and the API keys Grafana
// issued before service accounts.
//
// A service account token carries a CRC32 checksum that is verified
// offline, so a well-formed lookalike is never reported. Cloud tokens and
// legacy API keys are base64-encoded JSON that names the organization and
// the token, which patty reads without contacting anyone. A service
// account token or API key is accepted by exactly one Grafana instance the
// token does not name, so verification asks the instances the operator
// passed with --grafana-url or GRAFANA_URL and the ones the scanned
// repository names; a Cloud token is checked against grafana.com. Nothing
// here is revocable by the holder: deleting a token needs a permission the
// token itself rarely has.
package grafana

import (
	"net/http"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider, detect.Configurable,
// detect.ServerVerifier and detect.InstanceObserver for Grafana.
type Provider struct {
	// CloudURL is the Grafana Cloud portal, https://grafana.com by default.
	CloudURL string
	Client   *http.Client
	// Configured are the Grafana instances the operator named with
	// --grafana-url or GRAFANA_URL. Configure reads the variable; the flag
	// is added to it by the command. They are contacted as given, plain
	// http included: naming one is the operator's decision.
	Configured []string
	// Policy decides which instances discovered in scanned content may be
	// contacted.
	Policy detect.ServerPolicy
}

const (
	// URLEnv is the environment variable Configure reads Configured from:
	// one or more instance URLs separated by commas or whitespace.
	URLEnv = "GRAFANA_URL"
	// URLFlag is the command line flag that adds instances to it.
	URLFlag = "--grafana-url"

	cloudPoliciesPage = "https://grafana.com/orgs/<org>/access-policies"
)

// New returns a Provider against the public Grafana Cloud portal, with no
// instances configured.
func New() *Provider {
	return &Provider{CloudURL: "https://grafana.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "Grafana" }

// Configure implements detect.Configurable: the instances to verify
// service account tokens and API keys against come from GRAFANA_URL.
func (p *Provider) Configure(env func(string) string) {
	p.Configured = SplitURLs(env(URLEnv))
}

// SplitURLs splits a list of instance URLs separated by commas or
// whitespace, dropping empty entries and trailing slashes.
func SplitURLs(list string) []string {
	var out []string
	for _, u := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if u = strings.TrimRight(u, "/"); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// AllowPrivateServers implements detect.ServerVerifier.
func (p *Provider) AllowPrivateServers(allow bool) { p.Policy.AllowPrivate = allow }

// Kinds implements detect.Provider. Nothing here is revocable through the
// API by the token's holder; every kind carries the owner's procedure.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindServiceAccountToken, Description: "service account token",
			RevokeNote: "on the instance it belongs to, under Administration → Service accounts, delete the token or the whole service account; the API needs serviceaccounts:write for that, which the token itself rarely has",
			AuditNote:  "the service account's token list on the instance shows when each token was last used; the instance's access log has the requests since the commit date. Grafana is not a GitHub secret scanning partner for service account tokens, so nobody revokes one on their own"},
		{Kind: KindCloudToken, Description: "Grafana Cloud access policy token", RevokePage: cloudPoliciesPage,
			RevokeNote: "with <org> the org named in the attribution: delete the token under its access policy, or the policy itself; the API needs accesspolicies:delete for that",
			AuditNote:  "Grafana Cloud is a GitHub secret scanning partner and revokes access policy tokens found in public repositories, so a token from public history may already be dead; confirm with --verify. The org's usage and billing pages show what the policy's stack received since the commit date"},
		{Kind: KindLegacyAPIKey, Description: "API key (legacy, pre-service-account)",
			RevokeNote: "on the instance it belongs to, under Administration → Service accounts (Grafana 9.1 and later list migrated API keys there) or Administration → API keys on older versions, delete the key",
			AuditNote:  "the instance's access log has the requests since the commit date; Grafana is not a GitHub secret scanning partner for API keys, so nobody revokes one on their own"},
	}
}

// LocalSources implements detect.Provider: the environment variables the
// Grafana tools and Terraform provider read, and the MCP server
// configurations of Claude Code and Claude Desktop, whose env blocks often
// hold a Grafana token. Only fingerprints are compared.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"GRAFANA_API_KEY", "GRAFANA_TOKEN", "GRAFANA_SERVICE_ACCOUNT_TOKEN", "GRAFANA_CLOUD_API_KEY", "GRAFANA_CLOUD_ACCESS_POLICY_TOKEN"},
		ConfigFiles: []string{"Claude/claude_desktop_config.json"},
		HomeFiles:   []string{".claude.json"},
	}
}
