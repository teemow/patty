// Package openai is the OpenAI credential provider: project, service
// account, admin and legacy user API keys.
//
// Every OpenAI key embeds the marker `T3BlbkFJ` ("OpenAI" in base64) at a
// fixed position, so the scan looks for the marker and checks the exact
// shape around it; the marker is not a checksum but it removes random
// look-alikes. Verification is one request that lists models, or the
// organization's admin keys for an admin key. OpenAI's API cannot revoke a
// key by itself: revocation goes through the Admin API with an admin key of
// the organization the leaked key belongs to, which the operator supplies in
// OPENAI_ADMIN_KEY. With one, patty finds the key in the organization's
// projects by the redacted value OpenAI shows for each key and deletes it.
package openai

import (
	"net/http"
	"sync"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for OpenAI.
type Provider struct {
	// BaseURL is the API root, https://api.openai.com by default.
	BaseURL string
	Client  *http.Client
	// AdminKey is an admin key of the operator's organization. It enables
	// deletion of that organization's keys and lets the report name them.
	// Configure reads it from OPENAI_ADMIN_KEY.
	AdminKey string

	mu      sync.Mutex
	entries map[detect.Kind][]entry // the organization's keys per family, fetched once
}

const (
	// AdminKeyEnv is the environment variable Configure reads AdminKey from.
	AdminKeyEnv = "OPENAI_ADMIN_KEY"

	keysPage      = "https://platform.openai.com/api-keys"
	adminKeysPage = "https://platform.openai.com/settings/organization/admin-keys"
)

// auditNote is what to check after a key leaked, and what OpenAI does on
// its own when it spots one.
const auditNote = "OpenAI is a GitHub secret scanning partner and disables keys found in public repositories, then emails the owner, so a key from public history is probably already disabled; confirm with --verify. The platform's usage page, filtered by API key, shows what it was used for since the commit date"

// New returns a Provider against the public OpenAI API.
func New() *Provider {
	return &Provider{BaseURL: "https://api.openai.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "OpenAI" }

// Configure implements detect.Configurable: the admin key comes from
// OPENAI_ADMIN_KEY.
func (p *Provider) Configure(env func(string) string) {
	p.AdminKey = env(AdminKeyEnv)
}

// Kinds implements detect.Provider. Project, service account and admin
// keys are revocable only while an admin key is configured; legacy user
// keys are not managed by the Admin API at all.
func (p *Provider) Kinds() []detect.KindInfo {
	admin := p.AdminKey != ""
	var note string
	if !admin {
		note = "or set " + AdminKeyEnv + " to an admin key of the organization and run again with --revoke to delete it from here"
	}
	marker := " (the T3BlbkFJ marker is not a checksum, but it removes random look-alikes)"
	return []detect.KindInfo{
		{Kind: KindProject, Description: "project key" + marker, Revocable: admin, RevokePage: keysPage, RevokeNote: note, AuditNote: auditNote},
		{Kind: KindServiceAccount, Description: "service account key" + marker, Revocable: admin, RevokePage: keysPage, RevokeNote: note, AuditNote: auditNote,
			RevokeEffect: "OpenAI may refuse to delete a service account's key on its own; deleting the service account under the project's settings removes it for certain"},
		{Kind: KindAdmin, Description: "admin key" + marker, Revocable: admin, RevokePage: adminKeysPage, RevokeNote: note, AuditNote: auditNote},
		{Kind: KindLegacy, Description: "legacy user key" + marker, RevokePage: keysPage,
			RevokeNote: "user keys from before projects are not listed by the Admin API, so --revoke cannot reach them", AuditNote: auditNote},
	}
}

// LocalSources implements detect.Provider: the environment variables the
// SDKs read, Codex's credential file (which holds a sign-in as well as a
// key) and opencode's credential store.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"OPENAI_API_KEY", AdminKeyEnv},
		ConfigFiles: []string{"opencode/auth.json"},
		HomeFiles:   []string{".codex/auth.json"},
	}
}
