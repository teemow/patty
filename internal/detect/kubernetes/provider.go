// Package kubernetes is the provider for the credentials that reach a
// Kubernetes API server: the client certificates, bearer tokens and basic
// auth logins a kubeconfig carries, service account tokens wherever they
// turn up, and Secret manifests committed with their values in the clear.
//
// None of them can be revoked through an API. A client certificate is valid
// until it expires or the cluster's CA is rotated; a service account token
// dies with the Secret or ServiceAccount that issued it. The report carries
// those procedures. Verification, with --verify, is one GET /version
// against the server the kubeconfig names, with the credential; a
// certificate or token found without a server is not sent anywhere.
// Servers on private addresses are refused unless --verify-private-servers
// is given: a repository must not be able to point patty at the network it
// runs in.
//
// A Secret manifest is reported even when no provider recognises its
// values: plaintext secret material in git is a leak whatever its shape.
// The values themselves are decoded and searched by the Registry, so a
// GitHub token inside one is GitHub's finding, attributed to the Secret.
package kubernetes

import (
	"context"
	"net"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for Kubernetes.
type Provider struct {
	// Timeout bounds the one request --verify makes per credential.
	Timeout time.Duration
	// LookupIP resolves a server's host before it is contacted, so that
	// a private address can be refused; tests fake it.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// allowPrivate lets verification contact servers on private,
	// loopback and link-local addresses.
	allowPrivate bool
}

// policy is the rule for the servers a kubeconfig names.
func (p *Provider) policy() detect.ServerPolicy {
	return detect.ServerPolicy{LookupIP: p.LookupIP, AllowPrivate: p.allowPrivate}
}

const (
	auditNote = "check the API server's audit log for requests by this identity since the commit date"
	// noRevocation is the fact every certificate finding has to carry.
	noRevocation = "Kubernetes has no certificate revocation: the identity stays valid until the certificate expires or the cluster's CA is rotated"
)

// New returns a Provider that resolves hosts through the system resolver.
func New() *Provider {
	return &Provider{
		Timeout: 10 * time.Second,
		LookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
	}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "Kubernetes" }

// Kinds implements detect.Provider. Nothing here is revocable through an
// API; every kind carries the procedure that retires it.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindClientCertificate, Description: "client certificate",
			RevokeNote: noRevocation + "; rotate the CA (`kubeadm certs renew` does not help, the old CA must stop being trusted) or wait for the expiry shown, and until then treat this identity as live",
			AuditNote:  auditNote},
		{Kind: KindServiceAccountToken, Description: "service account token",
			RevokeNote: "a legacy token dies with its Secret: `kubectl delete secret <name> -n <namespace>`; a bound token dies with its ServiceAccount: delete and recreate the ServiceAccount, then restart the workloads that use it so they get new tokens",
			AuditNote:  auditNote},
		{Kind: KindToken, Description: "bearer token",
			RevokeNote: "revoke it where it was issued: the OIDC provider, the webhook authenticator, or the static token file of the API server (which needs a restart)",
			AuditNote:  auditNote},
		{Kind: KindBasicAuth, Description: "basic auth login",
			RevokeNote: "remove the user from the API server's basic-auth file and restart it; basic auth has been removed from Kubernetes since 1.19, so rotate whatever still speaks it",
			AuditNote:  auditNote},
		{Kind: KindSecretManifest, Description: "Secret manifest with plaintext values", PublicValue: true, Opaque: true,
			RevokeNote: "delete and recreate the Secret in every cluster it was applied to, with new material, then take it out of git: encrypt it with sops or hand it to an external secrets operator; `--ignore " + string(KindSecretManifest) + "` leaves this kind out of the report",
			AuditNote:  "check the audit log of every cluster the Secret was applied to for use of whatever it protects since the commit date"},
	}
}

// LocalSources implements detect.Provider: the kubeconfig kubectl reads,
// and the files KUBECONFIG lists. Only certificate and token fingerprints
// are compared.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		EnvFiles:    []string{"KUBECONFIG"},
		ConfigFiles: []string{"kube/config"},
		HomeFiles:   []string{".kube/config"},
	}
}

// AllowPrivateServers implements detect.ServerVerifier.
func (p *Provider) AllowPrivateServers(allow bool) { p.allowPrivate = allow }
