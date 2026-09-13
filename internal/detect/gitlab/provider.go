// Package gitlab is the GitLab credential provider: personal access
// tokens and the other token families GitLab prefixes with `gl`: deploy,
// runner, CI job, pipeline trigger, feed, incoming mail, agent, OAuth
// application and feature flag tokens.
//
// A routable personal access token, the format GitLab issues since 2025,
// carries a CRC32 checksum that is verified offline and a payload that
// names the organization, group, project or user it belongs to, which
// patty reads without contacting anyone. Every other family is matched on
// prefix, alphabet and length. A token is accepted by one GitLab instance
// it does not name, so verification asks gitlab.com, the instances the
// operator passed with --gitlab-url or GITLAB_URL, and the ones the
// scanned repository names. A personal access token revokes itself; the
// other families are revoked by their owner, and the report says where.
package gitlab

import (
	"net/http"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider, detect.Revoker, detect.DryRunRevoker,
// detect.Configurable, detect.ServerVerifier and detect.InstanceObserver
// for GitLab.
type Provider struct {
	// DefaultURL is the instance every token is tried against first,
	// https://gitlab.com by default.
	DefaultURL string
	Client     *http.Client
	// Configured are the instances the operator named with --gitlab-url or
	// GITLAB_URL. Configure reads the variable; the flag is added to it by
	// the command. They are contacted as given, plain http included:
	// naming one is the operator's decision.
	Configured []string
	// Policy decides which instances discovered in scanned content may be
	// contacted.
	Policy detect.ServerPolicy
}

const (
	// URLEnv is the environment variable Configure reads Configured from:
	// one or more instance URLs separated by commas or whitespace.
	URLEnv = "GITLAB_URL"
	// URLFlag is the command line flag that adds instances to it.
	URLFlag = "--gitlab-url"

	patPage = "https://gitlab.com/-/user_settings/personal_access_tokens"
	// notPartner is the fact every GitLab finding in a GitHub repository
	// has to carry.
	notPartner = "GitLab is not a GitHub secret scanning partner: a token leaked into a GitHub repository is revoked by nobody but its owner"
)

// New returns a Provider against gitlab.com, with no other instance
// configured.
func New() *Provider {
	return &Provider{DefaultURL: "https://gitlab.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "GitLab" }

// Configure implements detect.Configurable: the self-managed instances to
// verify tokens against come from GITLAB_URL.
func (p *Provider) Configure(env func(string) string) {
	p.Configured = splitURLs(env(URLEnv))
}

// splitURLs splits a list of instance URLs separated by commas or
// whitespace, dropping empty entries and trailing slashes.
func splitURLs(list string) []string {
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

// Kinds implements detect.Provider. Only a personal access token revokes
// itself; every other family carries the owner's procedure.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindPAT, Description: "personal access token (routable tokens carry a CRC32 checksum)", Revocable: true, RevokePage: patPage,
			RevokeNote: "on a self-managed instance, the same page under the instance's own host",
			AuditNote:  notPartner + ". --verify shows when the token was last used; the instance's audit events (Admin → Monitoring → Audit events, or the audit_events API) list what it did since the commit date"},
		{Kind: KindDeployToken, Description: "deploy token",
			RevokeNote: "in the project or group it belongs to, Settings → Repository → Deploy tokens: revoke it; a deploy token is only usable together with its username (gitlab+deploy-token-N)",
			AuditNote:  notPartner + ". A deploy token reads the repository and the container registry without leaving a trace in the audit events; assume both were read"},
		{Kind: KindRunnerToken, Description: "runner authentication token",
			RevokeNote: "in the project, group or Admin area, Settings → CI/CD → Runners: delete the runner or reset its authentication token, then re-register the runner; whoever holds the token can pick up jobs and their variables meanwhile",
			AuditNote:  notPartner + ". The runner's job list on the instance shows the jobs it ran since the commit date; a stranger's runner would show up there with an unfamiliar host"},
		{Kind: KindJobToken, Description: "CI job token",
			RevokeNote: "a job token expires when its job ends, so there is nothing to revoke; check what the job's project allowed job tokens to reach (Settings → CI/CD → Job token permissions)",
			AuditNote:  "a job token is valid for minutes; its job's log and duration say how long"},
		{Kind: KindTriggerToken, Description: "pipeline trigger token",
			RevokeNote: "in the project, Settings → CI/CD → Pipeline trigger tokens: revoke it; whoever holds it can start pipelines with variables of their choosing until then",
			AuditNote:  notPartner + ". The project's pipelines since the commit date show which were started by a trigger"},
		{Kind: KindFeedToken, Description: "feed token",
			RevokeNote: "in User Settings → Access Tokens, reset the feed token; it reads every issue and merge request the user can see, through the RSS feeds",
			AuditNote:  notPartner + "; feed reads leave no audit event"},
		{Kind: KindIncomingMailToken, Description: "incoming mail token",
			RevokeNote: "in User Settings → Access Tokens, reset the incoming email token; whoever holds it can create issues and comments as the user by email",
			AuditNote:  notPartner + ". Issues and comments created by email as the user since the commit date are the trace"},
		{Kind: KindAgentToken, Description: "agent for Kubernetes token",
			RevokeNote: "in the project, Operate → Kubernetes clusters → the agent → Access tokens: revoke it; whoever holds it can connect an agent of their own to the instance and receive the manifests and CI/CD tunnel the agent is entitled to",
			AuditNote:  notPartner + ". The agent's activity log on the instance shows connections since the commit date"},
		{Kind: KindOAuthAppSecret, Description: "OAuth application secret",
			RevokeNote: "in User Settings → Applications, the group's Settings → Applications, or Admin → Applications: renew the secret, then update the application that uses it; the secret alone does not sign anyone in, it needs a grant, but with one it mints tokens for every user of the application",
			AuditNote:  notPartner + ". Tokens minted with the secret appear as the application's under each user's Applications page"},
		{Kind: KindFeatureFlagClientToken, Description: "feature flag client (Unleash instance) token",
			RevokeNote: "in the project, Deploy → Feature flags → Configure: regenerate the instance ID; whoever holds it reads the project's feature flag definitions and their strategies",
			AuditNote:  notPartner + "; feature flag reads leave no audit event"},
		{Kind: KindSCIMToken, Description: "SCIM token",
			RevokeNote: "in the group, Settings → SAML SSO → SCIM: reset the token, then update the identity provider; whoever holds it provisions and deprovisions members of the group",
			AuditNote:  notPartner + ". The group's audit events list members added and removed since the commit date"},
	}
}

// LocalSources implements detect.Provider: the glab CLI's configuration,
// the environment variables glab, python-gitlab, Terraform and GitLab CI
// read, and git's credential stores, whose entries for a GitLab host hold
// a token as the password.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN", "CI_JOB_TOKEN"},
		ConfigFiles: []string{"glab-cli/config.yml"},
		HomeFiles:   []string{".netrc", ".git-credentials"},
	}
}
