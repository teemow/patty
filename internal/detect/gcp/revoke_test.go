package gcp

import (
	"context"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestRevoke(t *testing.T) {
	p, calls := server(t)
	access := detect.Token{Kind: KindAccessToken, Value: accessToken("Liv3")}
	refresh := detect.Token{Kind: KindUserCredentials, Value: refreshToken("Liv3"), Secret: credential{ClientID: clientID, ClientSecret: "s"}.encode()}
	bare := detect.Token{Kind: KindRefreshToken, Value: refreshToken("Bare")}
	dead := detect.Token{Kind: KindAccessToken, Value: accessPrefix + strings.Repeat("dead", 25)}
	if err := p.Revoke(context.Background(), []detect.Token{access, refresh, bare, dead}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got := calls()
	if len(got) != 4 {
		t.Fatalf("%d requests, want one revoke per token: %+v", len(got), got)
	}
	for i, tok := range []detect.Token{access, refresh, bare, dead} {
		if got[i].path != "/revoke" || got[i].form["token"] != tok.Value {
			t.Errorf("request %d: %+v", i, got[i])
		}
		if _, sent := got[i].form["client_secret"]; sent {
			t.Error("the client secret is not needed to revoke and must not be sent")
		}
	}
	broken := detect.Token{Kind: KindAccessToken, Value: accessPrefix + strings.Repeat("broken", 20)}
	if err := p.Revoke(context.Background(), []detect.Token{broken}); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("broken: %v", err)
	}
}

func TestRevokeNotRevocable(t *testing.T) {
	p, calls := server(t)
	err := p.Revoke(context.Background(), []detect.Token{
		serviceAccountToken(t, nil),
		{Kind: KindAPIKey, Value: apiKey("k")},
	})
	if err == nil || !strings.Contains(err.Error(), serviceAccountsPage) || !strings.Contains(err.Error(), credentialsPage) {
		t.Errorf("Revoke: %v", err)
	}
	if len(calls()) != 0 {
		t.Errorf("something was sent for a kind nothing can revoke: %+v", calls())
	}
	for _, k := range p.Kinds() {
		if k.Revocable != revocable(k.Kind) {
			t.Errorf("%s: Revocable %v but revoke says %v", k.Kind, k.Revocable, revocable(k.Kind))
		}
	}
}

func TestDryRunRevoke(t *testing.T) {
	p, calls := server(t)
	if err := p.DryRunRevoke(context.Background(), detect.Token{Kind: KindAccessToken, Value: accessToken("Liv3")}); err != nil {
		t.Errorf("live: %v", err)
	}
	if err := p.DryRunRevoke(context.Background(), detect.Token{Kind: KindAccessToken, Value: accessPrefix + strings.Repeat("dead", 25)}); err == nil || !strings.Contains(err.Error(), "already rejected") {
		t.Errorf("dead: %v", err)
	}
	if err := p.DryRunRevoke(context.Background(), detect.Token{Kind: KindRefreshToken, Value: refreshToken("Bare")}); err == nil || !strings.Contains(err.Error(), "client id and secret") {
		t.Errorf("bare refresh: %v", err)
	}
	if err := p.DryRunRevoke(context.Background(), detect.Token{Kind: KindAPIKey, Value: apiKey("k")}); err == nil {
		t.Error("an API key has no revocation to rehearse")
	}
	for _, c := range calls() {
		if c.path == "/revoke" {
			t.Error("the dry run revoked something")
		}
	}
}
