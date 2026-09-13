package detect

import (
	"context"
	"errors"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// fake is a provider that finds its own name and marks its kind revocable
// without being able to revoke it, enough to exercise the registry.
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
func (fake) LocalSources() LocalSources { return LocalSources{} }

// revoking is a fake whose API revokes its credentials.
type revoking struct{ fake }

func (revoking) Revoke(context.Context, []Token) error { return nil }

// correlating is a fake that also relates its credentials to content.
type correlating struct{ fake }

func (c correlating) Observe(content []byte) []Sighting {
	if strings.Contains(string(content), "encrypted to "+c.name) {
		return Sightings([]string{c.name + "-public"})
	}
	return nil
}
func (c correlating) Identifiers(Token) []string { return []string{c.name + "-public"} }

func TestRegistryCorrelators(t *testing.T) {
	r := NewRegistry(fake{"alpha"}, correlating{fake{"beta"}})
	cs := r.Correlators()
	if len(cs) != 1 || cs[0].Observe([]byte("encrypted to beta")) == nil || cs[0].Observe([]byte("plain")) != nil {
		t.Fatalf("correlators = %+v", cs)
	}
	if NewRegistry(fake{"alpha"}).Correlators() != nil {
		t.Fatal("no correlators must be nil")
	}
}

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
	r := NewRegistry(revoking{fake{"alpha"}}, fake{"beta"})
	if len(r.Providers()) != 2 || r.ProviderName("beta-token") != "beta" || r.Provider("beta-token").Name() != "beta" {
		t.Fatal("provider lookup by kind")
	}
	if !r.Revocable("alpha-token") || r.RevokePage("alpha-token") != "https://alpha" || r.Info("alpha-token").Kind != "alpha-token" {
		t.Fatal("kind info")
	}
	if v := r.Verify(context.Background(), Token{Kind: "beta-token"}); v.Status != StatusActive || v.Detail != "beta" {
		t.Fatalf("verify dispatch: %+v", v)
	}
	if r.Revocable("beta-token") || !r.Info("beta-token").Revocable {
		t.Fatal("a kind is only revocable when its provider is a Revoker")
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

func TestUnreachable(t *testing.T) {
	dns := &url.Error{Op: "Get", URL: "https://grafana.example.invalid/api/user", Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "grafana.example.invalid", IsNotFound: true}}}
	if v := Unreachable("grafana.example.invalid", dns); v.Status != StatusUnknown || v.Detail != "grafana.example.invalid not reachable from here: no such host" {
		t.Errorf("dns: %+v", v)
	}
	tls := &url.Error{Op: "Get", URL: "https://a.example.invalid/", Err: errors.New("tls: failed to verify certificate")}
	if v := Unreachable("a.example.invalid", tls); v.Detail != "a.example.invalid not reachable from here: tls: failed to verify certificate" {
		t.Errorf("tls: %+v", v)
	}
	if v := Unreachable("server", errors.New("connection refused")); v.Detail != "server not reachable from here: connection refused" {
		t.Errorf("plain: %+v", v)
	}
}

func TestScanHostsWantsAPublicTopLevelDomain(t *testing.T) {
	content := []byte("grafana.yaml grafana.ini grafana.home grafana.local grafana.example.com-tls https://grafana.example.com:3000/ grafana.home.arpa")
	got := ScanHosts(content, "grafana.", func(string) bool { return true })
	want := []string{"https://grafana.example.com:3000", "https://grafana.home.arpa"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanHosts = %v, want %v", got, want)
	}
}
