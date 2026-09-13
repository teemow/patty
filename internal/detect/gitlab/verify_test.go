package gitlab

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// instance is a GitLab that knows tokens by role: "live" is a personal
// access token, "narrow" one without api scope, "listed-revoked" one the
// instance answers 200 for but marks revoked, "runner" a runner token,
// deploy login "gitlab+deploy-token-7" with password "deploy" a deploy
// token; everything else is rejected.
type instance struct {
	mu      sync.Mutex
	calls   []string
	deleted []string
}

func (i *instance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls = append(i.calls, r.Method+" "+r.URL.RequestURI())
	if r.Header.Get("User-Agent") != detect.UserAgent {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case selfPath:
		switch tok := r.Header.Get("PRIVATE-TOKEN"); {
		case tok == "live" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"id":5,"name":"ci","revoked":false,"active":true,"scopes":["api","read_repository"],"user_id":12,"expires_at":"2027-02-03","last_used_at":"2026-09-01T10:00:00.000Z"}`))
		case tok == "live" && r.Method == http.MethodDelete:
			i.deleted = append(i.deleted, tok)
			w.WriteHeader(http.StatusNoContent)
		case tok == "listed-revoked":
			_, _ = w.Write([]byte(`{"id":6,"name":"old","revoked":true,"active":false,"scopes":["api"],"user_id":12}`))
		case tok == "narrow":
			w.WriteHeader(http.StatusForbidden)
		case tok == "flaky":
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	case runnerPath:
		_ = r.ParseForm()
		if r.Form.Get("token") == "runner" {
			_, _ = w.Write([]byte(`{"id":33,"token":"runner","token_expires_at":null}`))
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	case "/jwt/auth":
		user, pass, _ := r.BasicAuth()
		if r.URL.Query().Get("service") == "container_registry" && user == "gitlab+deploy-token-7" && pass == "deploy" {
			_, _ = w.Write([]byte(`{"token":"jwt"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newInstance(t *testing.T, tls bool) (*instance, *httptest.Server) {
	t.Helper()
	i := &instance{}
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(i)
	} else {
		srv = httptest.NewServer(i)
	}
	t.Cleanup(srv.Close)
	return i, srv
}

// provider returns a Provider whose default instance is srv.
func provider(srv *httptest.Server) *Provider {
	return &Provider{DefaultURL: srv.URL, Client: srv.Client()}
}

func TestVerifyPAT(t *testing.T) {
	_, srv := newInstance(t, false)
	p := provider(srv)
	ctx := context.Background()
	host := detect.HostOf(srv.URL)
	got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "live"})
	if got.Status != detect.StatusActive || got.Detail != "accepted by "+host+": token ci, user id 12, scopes api read_repository, last used 2026-09-01" || got.Expires != "2027-02-03" {
		t.Fatalf("live: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "listed-revoked"}); got.Status != detect.StatusRevoked || !strings.Contains(got.Detail, "lists it as revoked") {
		t.Fatalf("listed as revoked: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "narrow"}); got.Status != detect.StatusActive || !strings.Contains(got.Detail, "scopes do not allow") {
		t.Fatalf("narrow: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "dead"}); got.Status != detect.StatusRevoked || got.Detail != host+" rejects it" {
		t.Fatalf("dead: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "flaky"}); got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "HTTP 502") {
		t.Fatalf("flaky: %+v", got)
	}
}

func TestVerifyAcrossInstances(t *testing.T) {
	// The default instance rejects everything the second one knows.
	_, dflt := newInstance(t, false)
	second, other := newInstance(t, false)
	p := provider(dflt)
	p.Configured = []string{other.URL + "/"}
	ctx := context.Background()

	// "live" is accepted by both; the default answers first and settles it.
	got := p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "live"})
	if got.Status != detect.StatusActive || !strings.Contains(got.Detail, detect.HostOf(dflt.URL)) || len(second.calls) != 0 {
		t.Fatalf("first instance settles it: %+v, %v", got, second.calls)
	}
	// Both reject: revoked, each named.
	got = p.Verify(ctx, detect.Token{Kind: KindPAT, Value: "dead"})
	if got.Status != detect.StatusRevoked || !strings.Contains(got.Detail, detect.HostOf(dflt.URL)+" rejects it") || !strings.Contains(got.Detail, detect.HostOf(other.URL)+" rejects it") {
		t.Fatalf("dead everywhere: %+v", got)
	}
	// A discovered instance that duplicates a configured one is tried once.
	tok := p.Bind(detect.Token{Kind: KindPAT, Value: "dead"}, []string{other.URL})
	second.calls = nil
	p.Verify(ctx, tok)
	if len(second.calls) != 1 {
		t.Fatalf("duplicate instance tried %d times", len(second.calls))
	}
}

func TestVerifyRunnerAndDeployTokens(t *testing.T) {
	_, srv := newInstance(t, false)
	p := provider(srv)
	ctx := context.Background()
	host := detect.HostOf(srv.URL)
	if got := p.Verify(ctx, detect.Token{Kind: KindRunnerToken, Value: "runner"}); got.Status != detect.StatusActive || got.Detail != "runner token accepted by "+host+", runner 33" {
		t.Fatalf("runner: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindRunnerToken, Value: "gone"}); got.Status != detect.StatusRevoked {
		t.Fatalf("gone runner: %+v", got)
	}
	deploy := detect.Token{Kind: KindDeployToken, Value: "deploy", Secret: companion{Username: "gitlab+deploy-token-7"}.encode()}
	if got := p.Verify(ctx, deploy); got.Status != detect.StatusActive || got.Detail != "accepted by "+host+" as gitlab+deploy-token-7" {
		t.Fatalf("deploy: %+v", got)
	}
	deploy.Value = "revoked"
	if got := p.Verify(ctx, deploy); got.Status != detect.StatusRevoked {
		t.Fatalf("revoked deploy: %+v", got)
	}
	deploy.Secret = ""
	if got := p.Verify(ctx, deploy); got.Status != detect.StatusUnverifiable || !strings.Contains(got.Detail, "without its username") {
		t.Fatalf("deploy without username: %+v", got)
	}
}

// noNetwork is a transport that fails the test on any request.
type noNetwork struct{ t *testing.T }

func (n noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("a request was made to %s", r.URL)
	return nil, errors.New("no network in this test")
}

func TestOtherFamiliesAreNeverSent(t *testing.T) {
	p := New()
	p.Client = &http.Client{Transport: noNetwork{t}}
	for kind := range unverifiable {
		got := p.Verify(context.Background(), detect.Token{Kind: kind, Value: "v"})
		if got.Status != detect.StatusUnverifiable || got.Detail == "" {
			t.Errorf("%s: %+v", kind, got)
		}
	}
	if len(unverifiable) != len(families)-3 {
		t.Fatalf("%d families have nobody to ask; PATs, runner and deploy tokens are the verifiable ones", len(unverifiable))
	}
}

func TestVerifyDiscoveredInstancesFollowThePolicy(t *testing.T) {
	// The default instance rejects everything; the discovered ones accept the token.
	dsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer dsrv.Close()
	plain, psrv := newInstance(t, false)
	secure, ssrv := newInstance(t, true)
	p := &Provider{DefaultURL: dsrv.URL, Client: ssrv.Client()}
	ctx := context.Background()
	tok := p.Bind(detect.Token{Kind: KindPAT, Value: "live"}, []string{psrv.URL, ssrv.URL})

	got := p.Verify(ctx, tok)
	if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "rejects it") || !strings.Contains(got.Detail, "not https") || !strings.Contains(got.Detail, "private network") {
		t.Fatalf("refused: %+v", got)
	}
	if len(plain.calls)+len(secure.calls) != 0 {
		t.Fatal("a refused instance must not be contacted")
	}
	p.AllowPrivateServers(true)
	got = p.Verify(ctx, tok)
	if got.Status != detect.StatusActive || !strings.Contains(got.Detail, detect.HostOf(ssrv.URL)) || len(plain.calls) != 0 {
		t.Fatalf("allowed: %+v (plain calls %v)", got, plain.calls)
	}
}

func TestRevokeAndDryRun(t *testing.T) {
	first, fsrv := newInstance(t, false)
	second, ssrv := newInstance(t, false)
	p := provider(fsrv)
	p.Configured = []string{ssrv.URL}
	ctx := context.Background()
	live := detect.Token{Kind: KindPAT, Value: "live"}

	if err := p.DryRunRevoke(ctx, live); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if err := p.DryRunRevoke(ctx, detect.Token{Kind: KindPAT, Value: "dead"}); err == nil || !strings.Contains(err.Error(), "no candidate instance accepts it") {
		t.Fatalf("dry run of a dead token: %v", err)
	}
	if err := p.DryRunRevoke(ctx, detect.Token{Kind: KindDeployToken, Value: "d"}); err == nil || !strings.Contains(err.Error(), "cannot be revoked") {
		t.Fatalf("dry run of a deploy token: %v", err)
	}
	if len(first.deleted)+len(second.deleted) != 0 {
		t.Fatal("a dry run deletes nothing")
	}

	if err := p.Revoke(ctx, []detect.Token{live}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(first.deleted) != 1 || len(second.deleted) != 0 {
		t.Fatalf("the first instance that accepts the token revokes it: %v %v", first.deleted, second.deleted)
	}
	err := p.Revoke(ctx, []detect.Token{{Kind: KindPAT, Value: "dead"}})
	if err == nil || !strings.Contains(err.Error(), "no candidate instance accepts") {
		t.Fatalf("revoking a dead token: %v", err)
	}
	err = p.Revoke(ctx, []detect.Token{{Kind: KindRunnerToken, Value: "runner"}})
	if err == nil || !strings.Contains(err.Error(), "cannot be revoked through the API") {
		t.Fatalf("revoking a runner token: %v", err)
	}
}
