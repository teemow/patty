package detect

import (
	"context"
	"strings"
	"testing"
)

// fake is a provider that finds the word "secret" and reports every kind as
// revocable, enough to exercise the registry.
type fake struct{ name string }

func (f fake) Name() string { return f.name }
func (f fake) Kinds() []KindInfo {
	return []KindInfo{{Kind: Kind(f.name + "-token"), Revocable: true, RevokePage: "https://" + f.name}}
}
func (f fake) Find(content []byte) []Token {
	return ScanPrefix(nil, content, f.name, func(start int) (Token, bool) {
		return Token{Kind: Kind(f.name + "-token"), Value: f.name, Offset: start}, true
	})
}
func (f fake) Verify(context.Context, Token) Verification {
	return Verification{Status: StatusActive, Detail: f.name}
}
func (fake) Revoke(context.Context, []string) error { return nil }
func (fake) LocalSources() LocalSources             { return LocalSources{} }

func TestRegistryFindMergesAndNumbersLines(t *testing.T) {
	r := NewRegistry(fake{"alpha"}, fake{"beta"})
	got := r.Find([]byte("beta\nx alpha\nbeta"))
	if len(got) != 3 || got[0].Value != "beta" || got[1].Value != "alpha" || got[2].Value != "beta" {
		t.Fatalf("want [beta alpha beta] by offset, got %+v", got)
	}
	if got[0].Line != 1 || got[1].Line != 2 || got[2].Line != 3 {
		t.Fatalf("wrong line numbers: %+v", got)
	}
	if r.Find([]byte("nothing")) != nil {
		t.Fatal("no findings must be nil")
	}
}

func TestRegistryDispatch(t *testing.T) {
	r := NewRegistry(fake{"alpha"}, fake{"beta"})
	if len(r.Providers()) != 2 || r.ProviderName("beta-token") != "beta" || r.Provider("beta-token").Name() != "beta" {
		t.Fatal("provider lookup by kind")
	}
	if !r.Revocable("alpha-token") || r.RevokePage("alpha-token") != "https://alpha" || r.Info("alpha-token").Kind != "alpha-token" {
		t.Fatal("kind info")
	}
	if v := r.Verify(context.Background(), Token{Kind: "beta-token"}); v.Status != StatusActive || v.Detail != "beta" {
		t.Fatalf("verify dispatch: %+v", v)
	}
	if r.Revocable("nope") || r.RevokePage("nope") != "" || r.Provider("nope") != nil || r.ProviderName("nope") != "" {
		t.Fatal("unknown kind must be harmless")
	}
	if v := r.Verify(context.Background(), Token{Kind: "nope"}); v.Status != StatusUnknown {
		t.Fatalf("unknown kind verifies as unknown, got %+v", v)
	}
}

func TestRedactAndFingerprint(t *testing.T) {
	tok := "ghp_" + strings.Repeat("A", 36)
	r := Redact(tok)
	if r != "ghp_AAAA…AAAA" {
		t.Fatalf("bad redaction %q", r)
	}
	if Redact("short") != "short" {
		t.Fatal("short values pass through")
	}
	url := "https://example.invalid/services/T0123/B0456/" + strings.Repeat("x", 24)
	if got := Redact(url); got != "https://example.invalid/services/T0123/B0456/xx…xxxx" {
		t.Fatalf("url redaction keeps the path and hides the secret segment, got %q", got)
	}
	fp := Fingerprint(tok)
	if len(fp) != 16 || fp != (Token{Value: tok}).Fingerprint() {
		t.Fatalf("bad fingerprint %q", fp)
	}
}

func TestIssuer(t *testing.T) {
	if (Verification{App: "GitHub CLI", ClientID: "x"}).Issuer() != "GitHub CLI" || (Verification{ClientID: "x"}).Issuer() != "OAuth app x" || (Verification{}).Issuer() != "" {
		t.Fatal("issuer")
	}
}
