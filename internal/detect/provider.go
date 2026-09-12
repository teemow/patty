package detect

import (
	"bytes"
	"context"
	"sort"
)

// Provider is one credential issuer: it knows the token formats it hands
// out, how to ask whether one is still live, and how to revoke it.
//
// A provider never stores or logs a token value, and never contacts its API
// from Find.
type Provider interface {
	// Name is how the provider is called in reports: "GitHub", "Slack".
	Name() string
	// Kinds describes every credential family the provider detects.
	Kinds() []KindInfo
	// Find returns every credential of this provider in content. Offsets
	// are set; line numbers are filled in by the Registry.
	Find(content []byte) []Token
	// Verify asks the provider whether the credential is still accepted.
	// Only the provider's explicit invalid-credentials answer is reported as
	// revoked; anything else that is not a clean acceptance is unknown.
	Verify(ctx context.Context, tok Token) Verification
	// Revoke asks the provider to revoke the given credentials. A nil error
	// means every request was accepted; the caller confirms the outcome with
	// Verify.
	Revoke(ctx context.Context, tokens []Token) error
	// LocalSources lists where tools keep this provider's credentials on a
	// developer machine.
	LocalSources() LocalSources
}

// DryRunRevoker is a Provider whose revocation endpoint can rehearse a
// revocation: it answers as it would for the real request without revoking
// anything. patty uses it to preview a revocation before asking for
// confirmation.
type DryRunRevoker interface {
	DryRunRevoke(ctx context.Context, tok Token) error
}

// KindInfo describes one credential family.
type KindInfo struct {
	Kind Kind
	// Description is the human name: "personal access token (classic)".
	Description string
	// Revocable reports whether the provider's revocation endpoint accepts this kind.
	Revocable bool
	// RevokePage is where the owner revokes a credential of this kind by hand.
	RevokePage string
	// RevokeNote is added to the manual revocation advice when the API cannot
	// revoke the kind: what to check instead, or why it does not matter.
	RevokeNote string
	// RevokeEffect names a side effect of revoking through the API that is
	// easy to miss. The placeholder {app} stands for the issuing application.
	RevokeEffect string
	// AuditNote says how to find out whether a leaked credential of this kind
	// was used while it was exposed, and what the provider does on its own
	// when it spots the leak. Shown for every finding, revoked or not.
	AuditNote string
}

// LocalSources names where a provider's credentials are configured on the
// machine running patty. Paths may contain globs.
type LocalSources struct {
	// Env lists environment variables tools read the credential from.
	Env []string
	// ConfigFiles are relative to the XDG config directory (~/.config).
	ConfigFiles []string
	// HomeFiles are relative to the home directory.
	HomeFiles []string
	// Commands print a credential to stdout, such as `gh auth token`.
	Commands [][]string
}

// Registry is the set of providers a scan looks for. It dispatches by Kind
// and merges the providers' findings into one offset-ordered list.
type Registry struct {
	providers []Provider
	kinds     map[Kind]KindInfo
	owner     map[Kind]Provider
}

// NewRegistry builds a registry from providers, in report order.
func NewRegistry(providers ...Provider) *Registry {
	r := &Registry{providers: providers, kinds: map[Kind]KindInfo{}, owner: map[Kind]Provider{}}
	for _, p := range providers {
		for _, k := range p.Kinds() {
			r.kinds[k.Kind] = k
			r.owner[k.Kind] = p
		}
	}
	return r
}

// Providers returns the registered providers in order.
func (r *Registry) Providers() []Provider {
	return r.providers
}

// Find returns every credential of every provider in content, sorted by
// offset, with line numbers filled in.
func (r *Registry) Find(content []byte) []Token {
	var found []Token
	for _, p := range r.providers {
		found = append(found, p.Find(content)...)
	}
	if len(found) == 0 {
		return nil
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Offset < found[j].Offset })
	for i := range found {
		found[i].Line = bytes.Count(content[:found[i].Offset], []byte{'\n'}) + 1
	}
	return found
}

// Provider returns the provider that issues credentials of this kind, or nil.
func (r *Registry) Provider(kind Kind) Provider {
	return r.owner[kind]
}

// ProviderName returns the name of the provider of this kind, or "".
func (r *Registry) ProviderName(kind Kind) string {
	if p := r.owner[kind]; p != nil {
		return p.Name()
	}
	return ""
}

// Info describes the kind; the zero KindInfo for an unknown one.
func (r *Registry) Info(kind Kind) KindInfo {
	return r.kinds[kind]
}

// Revocable reports whether the kind's provider revokes it through its API.
func (r *Registry) Revocable(kind Kind) bool {
	return r.kinds[kind].Revocable
}

// RevokePage is where the owner revokes a credential of this kind by hand.
func (r *Registry) RevokePage(kind Kind) string {
	return r.kinds[kind].RevokePage
}

// Verify dispatches to the token's provider.
func (r *Registry) Verify(ctx context.Context, tok Token) Verification {
	p := r.owner[tok.Kind]
	if p == nil {
		return Verification{Status: StatusUnknown, Detail: "no provider for " + string(tok.Kind)}
	}
	return p.Verify(ctx, tok)
}
