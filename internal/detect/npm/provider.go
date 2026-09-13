// Package npm is the npm registry credential provider: the access tokens
// npm has issued since 2021 (npm_…) and the UUID tokens before them.
//
// Neither carries a checksum. The new format is matched on prefix, length
// and alphabet; a legacy UUID is only a token as the `_authToken` of an
// .npmrc line, since a bare UUID is anything. An .npmrc line also names
// the registry the token is for, which may be a private one: verification
// and revocation then go there instead of registry.npmjs.org. A token is
// revoked with itself, through the same endpoint `npm token revoke` uses.
package npm

import (
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider, detect.Revoker, detect.DryRunRevoker
// and detect.ServerVerifier for npm.
type Provider struct {
	// RegistryURL is the public registry, https://registry.npmjs.org by
	// default; a token found in an .npmrc line for another registry is
	// checked against that one.
	RegistryURL string
	Client      *http.Client
	// Policy decides which private registries named in scanned content may
	// be contacted.
	Policy detect.ServerPolicy
}

const (
	publicRegistry = "https://registry.npmjs.org"
	tokensPage     = "https://www.npmjs.com/settings/<user>/tokens"
	auditNote      = "npm is a GitHub secret scanning partner and revokes tokens found in public repositories and in published packages, so a token from public history may already be dead; confirm with --verify. A token with publish rights is a supply chain risk: check the account's packages for versions published since the commit date (`npm view <pkg> time`) and the account's email for publish notifications"
)

// New returns a Provider against the public npm registry.
func New() *Provider {
	return &Provider{RegistryURL: publicRegistry, Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "npm" }

// AllowPrivateServers implements detect.ServerVerifier.
func (p *Provider) AllowPrivateServers(allow bool) { p.Policy.AllowPrivate = allow }

// Kinds implements detect.Provider. Both kinds revoke themselves through
// the registry's token API.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindAccessToken, Description: "access token", Revocable: true, RevokePage: tokensPage,
			RevokeNote: "with <user> the account --verify names; a token for a private registry is revoked in that registry's settings", AuditNote: auditNote},
		{Kind: KindLegacyToken, Description: "legacy token (UUID, from an .npmrc _authToken)", Revocable: true, RevokePage: tokensPage,
			RevokeNote: "with <user> the account --verify names; a token for a private registry is revoked in that registry's settings", AuditNote: auditNote},
	}
}

// LocalSources implements detect.Provider: the user's .npmrc, and the
// environment variables the npm CLI, setup-node and CI templates read.
// The project's .npmrc in the working directory is checked for every
// provider.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:       []string{"NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_CONFIG__AUTH"},
		HomeFiles: []string{".npmrc"},
	}
}
