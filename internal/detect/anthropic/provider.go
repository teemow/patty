// Package anthropic is the Anthropic credential provider: API keys, Admin
// API keys, and the OAuth access and refresh tokens Claude Code signs in
// with.
//
// No Anthropic credential carries a checksum. API and admin keys end in a
// fixed `AA`, which is padding rather than a checksum but still rules out
// random look-alikes; the OAuth families are matched on prefix, alphabet
// and length. Verification is one request that lists models, or reads the
// organization for an admin key. Anthropic's API cannot revoke a key by
// itself: revocation needs an Admin API key of the organization the leaked
// key belongs to, which the operator supplies in ANTHROPIC_ADMIN_KEY. With
// one, patty finds the key in the organization's key list by the partial
// hint Anthropic shows for each key and sets it to inactive.
package anthropic

import (
	"net/http"
	"sync"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for Anthropic.
type Provider struct {
	// BaseURL is the API root, https://api.anthropic.com by default.
	BaseURL string
	Client  *http.Client
	// AdminKey is an Admin API key of the operator's organization. It
	// enables revocation of that organization's API keys and lets the
	// report name them. Configure reads it from ANTHROPIC_ADMIN_KEY.
	AdminKey string

	mu   sync.Mutex
	keys []apiKey // the organization's key list, fetched once
}

const (
	// AdminKeyEnv is the environment variable Configure reads AdminKey from.
	AdminKeyEnv = "ANTHROPIC_ADMIN_KEY"

	keysPage      = "https://console.anthropic.com/settings/keys"
	adminKeysPage = "https://console.anthropic.com/settings/admin-keys"
)

// auditNote is what to check after a key leaked, and what Anthropic does
// on its own when it spots one.
const auditNote = "Anthropic is a GitHub secret scanning partner and disables API keys found in public repositories, so a key from public history is probably already disabled by Anthropic; confirm with --verify. The Console's usage page, filtered by API key, shows what it was used for since the commit date"

// logout is how an OAuth token is retired: it is bound to a Claude Code
// sign-in, not to a key the Console lists.
const logout = "run `claude auth logout` on the machine that signed in, or sign that session out under Settings on claude.ai; the access token expires on its own within hours, the refresh token does not"

// New returns a Provider against the public Anthropic API.
func New() *Provider {
	return &Provider{BaseURL: "https://api.anthropic.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "Anthropic" }

// Configure implements detect.Configurable: the admin key comes from
// ANTHROPIC_ADMIN_KEY.
func (p *Provider) Configure(env func(string) string) {
	p.AdminKey = env(AdminKeyEnv)
}

// Kinds implements detect.Provider. API keys are revocable only while an
// admin key is configured; without one the advice says how to get there.
func (p *Provider) Kinds() []detect.KindInfo {
	admin := p.AdminKey != ""
	var note string
	if !admin {
		note = "or set " + AdminKeyEnv + " to an Admin API key of the organization and run again with --revoke to deactivate it from here"
	}
	return []detect.KindInfo{
		{Kind: KindAPIKey, Description: "API key (the fixed AA suffix is padding, not a checksum, but it removes random look-alikes)", Revocable: admin, RevokePage: keysPage, RevokeNote: note, AuditNote: auditNote},
		{Kind: KindAdminKey, Description: "Admin API key (same AA suffix)", RevokePage: adminKeysPage,
			RevokeNote: "admin keys are only managed in the Console, the Admin API cannot deactivate them", AuditNote: auditNote},
		{Kind: KindOAuth, Description: "OAuth access token (Claude Code sign-in)", RevokeNote: logout},
		{Kind: KindRefresh, Description: "OAuth refresh token (Claude Code sign-in)", RevokeNote: logout},
	}
}

// LocalSources implements detect.Provider: the environment variables the
// SDKs and Claude Code read, Claude Code's credential and settings files,
// and opencode's credential store.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"ANTHROPIC_API_KEY", AdminKeyEnv, "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"},
		ConfigFiles: []string{"opencode/auth.json"},
		HomeFiles:   []string{".claude/.credentials.json", ".claude.json"},
	}
}
