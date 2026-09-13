package npm

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// fake is an npm registry that knows a few tokens by role: "live" is a
// publish token in the list, "auto" an automation token with a CIDR,
// "granular" authenticates but may not list tokens, "keyed" is only
// deleted by its record key, everything else is rejected.
type fake struct {
	mu      sync.Mutex
	deleted []string
	calls   []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("User-Agent") != detect.UserAgent {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	role := roleOf(tok)
	if role == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == whoamiPath && role == "busy":
		w.WriteHeader(http.StatusTooManyRequests)
	case r.URL.Path == whoamiPath:
		_, _ = w.Write([]byte(`{"username":"alice"}`))
	case r.URL.Path == tokensPath && role == "granular":
		w.WriteHeader(http.StatusForbidden)
	case r.URL.Path == tokensPath:
		_, _ = w.Write([]byte(`{"objects":[
			{"token":"npm_Live","key":"k-live","cidr_whitelist":null,"readonly":false,"automation":false,"created":"2026-03-01T10:00:00.000Z"},
			{"token":"npm_Auto","key":"k-auto","cidr_whitelist":["10.0.0.0/8"],"readonly":false,"automation":true,"created":"2026-04-02T10:00:00.000Z"},
			{"token":"npm_Keye","key":"k-keyed","cidr_whitelist":null,"readonly":true,"automation":false,"created":"2025-01-01T00:00:00.000Z"}
		],"total":3}`))
	case strings.HasPrefix(r.URL.Path, tokensPath+"/token/") && r.Method == http.MethodDelete:
		key := strings.TrimPrefix(r.URL.Path, tokensPath+"/token/")
		switch {
		case role == "keyed" && key == "k-keyed", role != "keyed" && key == tok:
			f.deleted = append(f.deleted, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// roles are the test tokens, built at runtime with the right shape.
var roles = map[string]string{
	"live":     accessToken("Live" + strings.Repeat("a", 32)),
	"auto":     accessToken("Auto" + strings.Repeat("b", 32)),
	"granular": accessToken("Gran" + strings.Repeat("c", 32)),
	"keyed":    accessToken("Keye" + strings.Repeat("d", 32)),
	"busy":     accessToken("Busy" + strings.Repeat("e", 32)),
}

func roleOf(tok string) string {
	for role, v := range roles {
		if v == tok {
			return role
		}
	}
	return ""
}

func newFake(t *testing.T) (*fake, *Provider) {
	t.Helper()
	f := &fake{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &Provider{RegistryURL: srv.URL, Client: srv.Client()}
}

func TestVerify(t *testing.T) {
	_, p := newFake(t)
	ctx := context.Background()
	tok := func(role string) detect.Token { return detect.Token{Kind: KindAccessToken, Value: roles[role]} }
	host := detect.HostOf(p.RegistryURL)
	if got := p.Verify(ctx, tok("live")); got.Status != detect.StatusActive || got.Detail != "user alice on "+host+", publish, created 2026-03-01" {
		t.Fatalf("live: %+v", got)
	}
	if got := p.Verify(ctx, tok("auto")); got.Status != detect.StatusActive || got.Detail != "user alice on "+host+", automation, created 2026-04-02, cidr 10.0.0.0/8" {
		t.Fatalf("automation: %+v", got)
	}
	if got := p.Verify(ctx, tok("granular")); got.Status != detect.StatusActive || got.Detail != "user alice on "+host {
		t.Fatalf("granular tokens are live without a list entry: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindLegacyToken, Value: uuid()}); got.Status != detect.StatusRevoked {
		t.Fatalf("dead: %+v", got)
	}
	if got := p.Verify(ctx, tok("busy")); got.Status != detect.StatusUnknown || got.Detail != "rate limited" {
		t.Fatalf("busy: %+v", got)
	}
}

func TestVerifyPrivateRegistryFollowsThePolicy(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	tok := detect.Token{Kind: KindAccessToken, Value: roles["live"], Secret: companion{Registry: "http://npm.internal.example.com"}.encode()}
	if got := p.Verify(ctx, tok); got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "not https") {
		t.Fatalf("plain private registry: %+v", got)
	}
	tok.Secret = companion{Registry: "https://npm.internal.example.com"}.encode()
	p.Policy.LookupIP = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.1.2.3")}, nil }
	if got := p.Verify(ctx, tok); got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "private network") {
		t.Fatalf("private registry: %+v", got)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused registry is not contacted: %v", f.calls)
	}
	// The public registry needs no admission, however it is spelled.
	tok.Secret = companion{Registry: publicRegistry + "/"}.encode()
	if got := p.Verify(ctx, tok); got.Status != detect.StatusActive {
		t.Fatalf("public registry: %+v", got)
	}
}

func TestRevokeAndDryRun(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	live := detect.Token{Kind: KindAccessToken, Value: roles["live"]}
	keyed := detect.Token{Kind: KindAccessToken, Value: roles["keyed"]}
	dead := detect.Token{Kind: KindLegacyToken, Value: uuid()}

	if err := p.DryRunRevoke(ctx, live); err != nil {
		t.Fatalf("dry run of a live token: %v", err)
	}
	if err := p.DryRunRevoke(ctx, dead); err == nil || !strings.Contains(err.Error(), "already rejects") {
		t.Fatalf("dry run of a dead token: %v", err)
	}
	if len(f.deleted) != 0 {
		t.Fatal("a dry run deletes nothing")
	}

	if err := p.Revoke(ctx, []detect.Token{live, keyed}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(f.deleted) != 2 || f.deleted[0] != roles["live"] || f.deleted[1] != "k-keyed" {
		t.Fatalf("deleted %v: the value first, the record key when the registry does not take the value", f.deleted)
	}
	err := p.Revoke(ctx, []detect.Token{dead})
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("revoking a dead token is refused: %v", err)
	}
}
