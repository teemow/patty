// Package pagerduty is the PagerDuty credential provider: REST API keys
// and the routing keys (integration keys) that send events to a service.
//
// An API key is twenty characters behind a two-character prefix and has no
// checksum; a routing key is 32 hex characters with no shape of its own at
// all, so it is only a finding under the configuration key that names it
// (`routing_key`, `service_key`, `integration_key`), in Alertmanager
// configuration, Terraform, YAML, JSON or an environment file. An API key
// is verified with one request that names the user it belongs to. A
// routing key is never verified: the only way to test one is to send an
// event, which pages the on-call. Neither can be revoked by the holder.
package pagerduty

import (
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for PagerDuty.
type Provider struct {
	// BaseURL is the REST API root, https://api.pagerduty.com by default.
	BaseURL string
	Client  *http.Client
}

// New returns a Provider against the public PagerDuty API.
func New() *Provider {
	return &Provider{BaseURL: "https://api.pagerduty.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "PagerDuty" }

// Kinds implements detect.Provider. PagerDuty's API revokes neither kind;
// each carries the owner's procedure.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindAPIKey, Description: "REST API key (general access or user)",
			RevokeNote: "a general access key (y_) is deleted under Integrations → Developer Tools → API Access Keys of the account, at https://<subdomain>.pagerduty.com/api_keys (the key does not name the subdomain; --verify names the account's users); a user key (u+) under My Profile → User Settings → API Access",
			AuditNote:  "the account's audit trail (Account Settings → Audit Trail, or the audit records API) lists the requests each key made since the commit date. PagerDuty is not a GitHub secret scanning partner and gitleaks has no rule for these keys, so nobody revokes one on their own"},
		{Kind: KindRoutingKey, Description: "routing key (Events API integration key)",
			RevokeNote: "open the service the key belongs to, Integrations, and regenerate the integration key, then update Alertmanager or whatever sends events with it; anyone holding the old key can page the on-call indefinitely until then",
			AuditNote:  "the service's incidents and alerts since the commit date show whether the key was used to page anyone; PagerDuty does not revoke routing keys on its own"},
	}
}

// LocalSources implements detect.Provider: the environment variables the
// PagerDuty CLIs and SDKs read, and the pd CLI's configuration.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"PAGERDUTY_TOKEN", "PAGERDUTY_API_KEY", "PD_API_KEY", "PAGERDUTY_USER_TOKEN", "PAGERDUTY_ROUTING_KEY"},
		ConfigFiles: []string{"pd/config.yaml"},
	}
}
