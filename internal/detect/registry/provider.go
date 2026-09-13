// Package registry is the provider for OCI and Docker registry credentials:
// the logins a Docker config keeps per registry, wherever that config is
// embedded (a config.json, a Kubernetes pull secret, Helm values, a
// Basic Authorization header aimed at a registry), and the native tokens of
// Docker Hub and Quay.
//
// A login is a username and a password for one host, so its name in reports
// is `host/username`, which is not secret; the password travels in
// Token.Secret and is never shown. When the password is itself a Docker Hub
// or Quay token the finding is that token, so the same credential is one
// finding whether it turns up in a pull secret or in a CI variable. When it
// is another provider's credential, a GitHub token used against ghcr.io, the
// login says so and that provider's finding carries the token.
//
// Verification is one anonymous probe of the registry's /v2/ endpoint
// followed by one token request with the login; no image or manifest is
// pulled. Only Docker Hub personal access tokens can revoke themselves;
// every other kind gets the owner's rotation procedure.
package registry

import (
	"net/http"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for container registries.
type Provider struct {
	// Scheme is how registry hosts are reached, https by default; tests
	// point it at an http test server.
	Scheme string
	// HubURL is the Docker Hub API root, https://hub.docker.com by default.
	HubURL string
	// QuayHost is where Quay tokens are checked, quay.io by default.
	QuayHost string
	Client   *http.Client
	// peers are the other providers, whose credentials may serve as a
	// registry password; see peer.
	peers []detect.Provider
	kinds map[detect.Kind]string
}

const (
	hubSecurityPage = "https://hub.docker.com/settings/security"
	hubOrgsPage     = "https://hub.docker.com/orgs"
	quayOrgPage     = "https://quay.io/organization/"
	quayUserPage    = "https://quay.io/user/"
	azurePortal     = "https://portal.azure.com/#browse/Microsoft.ContainerRegistry%2Fregistries"
	githubTokens    = "https://github.com/settings/tokens"
	gcpServiceAccts = "https://console.cloud.google.com/iam-admin/serviceaccounts"
	awsUsersPage    = "https://console.aws.amazon.com/iam/home#/users"
)

// pullSecretNote is the part of every login's advice that is easy to
// forget: a pull secret is not only in the repository.
const pullSecretNote = "a pull secret found in a Helm chart or GitOps repository is also installed in every cluster that deployed it, rotate it there too"

// New returns a Provider against the public registries. peers are the other
// providers; a registry password that is one of their credentials is
// reported as theirs.
func New(peers ...detect.Provider) *Provider {
	p := &Provider{
		Scheme:   "https",
		HubURL:   "https://hub.docker.com",
		QuayHost: "quay.io",
		Client:   &http.Client{Timeout: 30 * time.Second},
		peers:    peers,
		kinds:    map[detect.Kind]string{},
	}
	for _, peer := range peers {
		for _, k := range peer.Kinds() {
			p.kinds[k.Kind] = peer.Name() + " " + k.Description
		}
	}
	return p
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "Registry" }

// Kinds implements detect.Provider. Only a Docker Hub personal access token
// can be revoked through the API, by itself; everything else names where
// its owner rotates it.
func (*Provider) Kinds() []detect.KindInfo {
	login := func(kind detect.Kind, description, page, note string) detect.KindInfo {
		return detect.KindInfo{Kind: kind, Description: description, RevokePage: page, RevokeNote: note + "; " + pullSecretNote, PublicValue: true}
	}
	return []detect.KindInfo{
		{Kind: KindHubPAT, Description: "Docker Hub personal access token", Revocable: true, RevokePage: hubSecurityPage,
			RevokeNote: "a token found without its username cannot be verified, treat it as live: deactivate it under Personal access tokens"},
		{Kind: KindHubOAT, Description: "Docker Hub organization access token", RevokePage: hubOrgsPage,
			RevokeNote: "deactivate it under the organization's Settings → Access tokens"},
		{Kind: KindQuayRobot, Description: "Quay robot account token", RevokePage: quayOrgPage,
			RevokeNote: "regenerate the token under the organization's (or the user's) Robot Accounts; " + pullSecretNote},
		{Kind: KindQuayOAuth, Description: "Quay OAuth access token", RevokePage: quayUserPage,
			RevokeNote: "revoke it under the user's Applications → Authorized Applications, or delete the OAuth application that issued it"},
		login(KindHubLogin, "Docker Hub login", hubSecurityPage,
			"a password cannot be revoked, change it under Security and deactivate the access tokens listed there"),
		login(KindQuayLogin, "Quay login", quayOrgPage,
			"regenerate the robot's token under the organization's Robot Accounts, or change the user's password"),
		login(KindACRLogin, "Azure Container Registry login", azurePortal,
			"`az acr token credential delete -r <registry> -n <token> --password1` for a token, or Access keys → Regenerate for the admin user"),
		login(KindGHCRLogin, "GitHub Container Registry login", githubTokens,
			"the password is a GitHub token, revoke it as such"),
		login(KindGCRLogin, "Google Artifact Registry login", gcpServiceAccts,
			"the password is a service account key (`_json_key`) or a short-lived OAuth token (`oauth2accesstoken`); delete the key under the service account's Keys"),
		login(KindECRLogin, "Amazon ECR login", awsUsersPage,
			"nothing to revoke, the password expires within 12 hours of being minted; rotate the IAM credentials that minted it (see the AWS finding, if they leaked too)"),
		login(KindHarborLogin, "Harbor login", "",
			"regenerate the robot under the Harbor project's (or Administration's) Robot Accounts, or change the user's password"),
		login(KindRegistryLogin, "registry login", "",
			"rotate it wherever the registry keeps its users: its htpasswd file, its robot accounts, or the identity provider in front of it"),
	}
}

// LocalSources implements detect.Provider: the Docker config, podman's and
// helm's auth files, and the variables CI jobs pass a registry password in.
// Only a login's host and user are compared, so only a config file can
// match; a variable holding a bare password matches when the password is a
// Docker Hub token. An entry that names a credsStore or credHelper keeps
// its secret in the OS keychain, which is not read.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"DOCKER_PASSWORD", "REGISTRY_PASSWORD", "QUAY_PASSWORD", "ACR_PASSWORD", "CR_PAT"},
		EnvFiles:    []string{"REGISTRY_AUTH_FILE", "HELM_REGISTRY_CONFIG"},
		ConfigFiles: []string{"containers/auth.json", "helm/registry/config.json"},
		HomeFiles:   []string{".docker/config.json"},
	}
}

// hubHosts are the names Docker Hub goes by in a config.
var hubHosts = map[string]bool{"docker.io": true, "index.docker.io": true, "registry-1.docker.io": true, "registry.hub.docker.com": true}

// kindFor derives the credential kind from the registry host.
func kindFor(host string) detect.Kind {
	bare := strings.ToLower(host)
	if i := strings.IndexByte(bare, ':'); i >= 0 {
		bare = bare[:i]
	}
	switch {
	case hubHosts[bare]:
		return KindHubLogin
	case bare == "quay.io":
		return KindQuayLogin
	case strings.HasSuffix(bare, ".azurecr.io"):
		return KindACRLogin
	case bare == "ghcr.io":
		return KindGHCRLogin
	case bare == "gcr.io", strings.HasSuffix(bare, ".gcr.io"), strings.HasSuffix(bare, ".pkg.dev"):
		return KindGCRLogin
	case strings.Contains(bare, ".dkr.ecr.") && strings.HasSuffix(bare, ".amazonaws.com"), bare == "public.ecr.aws":
		return KindECRLogin
	case strings.Contains(bare, "harbor"):
		return KindHarborLogin
	}
	return KindRegistryLogin
}

// isHub reports whether the host is Docker Hub, whose logins are checked
// against hub.docker.com rather than the registry.
func isHub(host string) bool {
	return kindFor(host) == KindHubLogin
}

// registryDomains name hosts of the well-known registries; a Basic header
// or a bare token is only taken for a registry credential near one of them.
var registryDomains = []string{"docker.io", "quay.io", "azurecr.io", "ghcr.io", "gcr.io", "pkg.dev", "dkr.ecr.", "public.ecr.aws"}
