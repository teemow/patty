// Package github is the GitHub credential provider: classic and fine-grained
// personal access tokens, OAuth and GitHub App tokens.
//
// Classic tokens carry a CRC32 checksum that is verified offline, so a
// well-formed lookalike is never reported. Verification is one authenticated
// request; revocation goes through GitHub's unauthenticated endpoint for
// leaked credentials, which notifies the owner.
package github

import (
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for GitHub.
type Provider struct {
	// BaseURL is the API root, https://api.github.com by default.
	BaseURL string
	Client  *http.Client
}

// New returns a Provider against the public GitHub API.
func New() *Provider {
	return &Provider{BaseURL: "https://api.github.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "GitHub" }

// authorizationEffect is the side effect of revoking an OAuth or GitHub App
// token: the whole authorization goes with it.
const authorizationEffect = "revokes the whole authorization of {app}, every token it holds for this user, including current logins"

// Kinds implements detect.Provider.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindPAT, Description: "personal access token (classic)", Revocable: true, RevokePage: "https://github.com/settings/tokens"},
		{Kind: KindFineGrained, Description: "fine-grained personal access token", Revocable: true, RevokePage: "https://github.com/settings/personal-access-tokens"},
		{Kind: KindOAuth, Description: "OAuth access token", Revocable: true, RevokePage: "https://github.com/settings/applications", RevokeEffect: authorizationEffect},
		{Kind: KindUserToServer, Description: "GitHub App user-to-server token", Revocable: true, RevokePage: "https://github.com/settings/apps/authorizations", RevokeEffect: authorizationEffect},
		{Kind: KindRefresh, Description: "GitHub App refresh token", Revocable: true, RevokePage: "https://github.com/settings/apps/authorizations", RevokeEffect: authorizationEffect},
		{Kind: KindServerToServer, Description: "GitHub App installation token", RevokePage: "https://github.com/settings/installations", RevokeNote: "installation tokens expire within an hour anyway"},
	}
}

// LocalSources implements detect.Provider: where gh, hub, Copilot and git
// itself keep tokens.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env: []string{"GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"},
		ConfigFiles: []string{
			"gh/hosts.yml",
			"hub",
			"github-copilot/hosts.json",
			"github-copilot/apps.json",
			"git/credentials",
		},
		HomeFiles: []string{
			".git-credentials",
			".netrc",
			".gitconfig",
			".config/gh/hosts.yml",
		},
		// gh may keep its token in the system keyring rather than hosts.yml.
		Commands: [][]string{{"gh", "auth", "token"}},
	}
}
