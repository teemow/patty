package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestVerify(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/user" && gotAuth == "token live":
			w.Header().Set("X-OAuth-Scopes", "repo, read:org")
			_, _ = w.Write([]byte(`{"login":"patty"}`))
		case r.URL.Path == "/user" && gotAuth == "token cli":
			w.Header().Set("X-OAuth-Client-Id", "178c6fc778ccc68e1d6a")
			w.Header().Set("GitHub-Authentication-Token-Expiration", "2026-10-01 12:00:00 UTC")
			_, _ = w.Write([]byte(`{"login":"patty"}`))
		case r.URL.Path == "/user" && gotAuth == "token custom":
			w.Header().Set("X-OAuth-Client-Id", "Iv1.unknown")
			_, _ = w.Write([]byte(`{"login":"patty"}`))
		case r.URL.Path == "/installation/repositories" && gotAuth == "token app":
			_, _ = w.Write([]byte(`{"total_count":3}`))
		case gotAuth == "token flaky":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	p := &Provider{BaseURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()

	if got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "live"}); got.Status != detect.StatusActive || got.Detail != "user patty, scopes: repo, read:org" {
		t.Fatalf("live: %+v", got)
	}
	got := p.Verify(ctx, detect.Token{Kind: KindOAuth, Value: "cli"})
	if got.Status != detect.StatusActive || got.ClientID != "178c6fc778ccc68e1d6a" || got.App != "GitHub CLI" || got.Issuer() != "GitHub CLI" || got.Expires != "2026-10-01" {
		t.Fatalf("cli: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindOAuth, Value: "custom"}); got.App != "" || got.Issuer() != "OAuth app Iv1.unknown" || got.Expires != "" {
		t.Fatalf("custom: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "live"}); got.Issuer() != "" {
		t.Fatalf("pat has no issuer: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindServerToServer, Value: "app"}); got.Status != detect.StatusActive || got.Detail != "installation token with access to 3 repositories" {
		t.Fatalf("app: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindOAuth, Value: "dead"}); got.Status != detect.StatusRevoked {
		t.Fatalf("dead: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindFineGrained, Value: "flaky"}); got.Status != detect.StatusUnknown {
		t.Fatalf("flaky: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindRefresh, Value: "r"}); got.Status != detect.StatusUnverifiable {
		t.Fatalf("refresh: %+v", got)
	}
}

func TestExpiryDay(t *testing.T) {
	for in, want := range map[string]string{
		"2026-10-01 12:00:00 UTC":   "2026-10-01",
		"2026-10-01T23:30:00+02:00": "2026-10-01",
		"soon":                      "soon",
	} {
		if got := expiryDay(in); got != want {
			t.Errorf("expiryDay(%q) = %q, want %q", in, got, want)
		}
	}
}
