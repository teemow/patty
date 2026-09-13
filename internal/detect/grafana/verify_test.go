package grafana

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// instance serves /api/user for a fixed set of tokens: "live" is a service
// account, "admin" a Grafana admin, "limited" authenticates but may not
// read the endpoint, everything else is rejected.
func instance(t *testing.T, tls bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != userPath || r.Header.Get("User-Agent") != detect.UserAgent {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") {
		case "live":
			_, _ = w.Write([]byte(`{"id":7,"login":"sa-1-deploy","orgId":1,"isGrafanaAdmin":false}`))
		case "admin":
			_, _ = w.Write([]byte(`{"id":1,"login":"admin","orgId":2,"isGrafanaAdmin":true}`))
		case "limited":
			w.WriteHeader(http.StatusForbidden)
		case "flaky":
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestVerifyAgainstConfiguredInstances(t *testing.T) {
	a, _ := instance(t, false)
	b, _ := instance(t, false)
	p := New()
	p.Client = a.Client()
	p.Configured = []string{a.URL + "/", b.URL}
	ctx := context.Background()
	sa := detect.Token{Kind: KindServiceAccountToken, Value: "live"}
	if got := p.Verify(ctx, sa); got.Status != detect.StatusActive || got.Detail != "accepted by "+detect.HostOf(a.URL)+" as sa-1-deploy, org 1" {
		t.Fatalf("live: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindLegacyAPIKey, Value: "admin"}); got.Status != detect.StatusActive || !strings.HasSuffix(got.Detail, "as admin, org 2, Grafana admin") {
		t.Fatalf("admin: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindServiceAccountToken, Value: "limited"}); got.Status != detect.StatusActive || !strings.Contains(got.Detail, "not allowed to read /api/user") {
		t.Fatalf("limited: %+v", got)
	}
	// Every configured instance rejects it: revoked, each named.
	got := p.Verify(ctx, detect.Token{Kind: KindServiceAccountToken, Value: "dead"})
	if got.Status != detect.StatusRevoked || !strings.Contains(got.Detail, detect.HostOf(a.URL)+" rejects it") || !strings.Contains(got.Detail, detect.HostOf(b.URL)+" rejects it") {
		t.Fatalf("dead everywhere: %+v", got)
	}
	// One instance could not answer: no verdict.
	if got := p.Verify(ctx, detect.Token{Kind: KindServiceAccountToken, Value: "flaky"}); got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "HTTP 502") {
		t.Fatalf("flaky: %+v", got)
	}
}

func TestVerifyWithoutInstanceIsUnverifiable(t *testing.T) {
	p := New()
	got := p.Verify(context.Background(), detect.Token{Kind: KindServiceAccountToken, Value: "live"})
	if got.Status != detect.StatusUnverifiable || !strings.Contains(got.Detail, URLFlag) || !strings.Contains(got.Detail, URLEnv) {
		t.Fatalf("no instance: %+v", got)
	}
}

func TestVerifyDiscoveredInstancesFollowThePolicy(t *testing.T) {
	plain, plainRequests := instance(t, false)
	secure, secureRequests := instance(t, true)
	p := New()
	p.Client = secure.Client()
	ctx := context.Background()
	tok := p.Bind(detect.Token{Kind: KindServiceAccountToken, Value: "live"}, []string{plain.URL, secure.URL})

	// A discovered instance on the loopback is refused until the operator allows private servers.
	got := p.Verify(ctx, tok)
	if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "not https") || !strings.Contains(got.Detail, "private network") || !strings.Contains(got.Detail, detect.PrivateServersFlag) {
		t.Fatalf("refused: %+v", got)
	}
	if plainRequests.Load()+secureRequests.Load() != 0 {
		t.Fatal("a refused instance must not be contacted")
	}

	p.AllowPrivateServers(true)
	got = p.Verify(ctx, tok)
	if got.Status != detect.StatusActive || !strings.Contains(got.Detail, "accepted by "+detect.HostOf(secure.URL)) {
		t.Fatalf("allowed: %+v", got)
	}
	if plainRequests.Load() != 0 {
		t.Fatal("a discovered plain-http instance is never contacted")
	}

	// The same plain instance named by the operator is contacted as given.
	p.Configured = []string{plain.URL}
	if got := p.Verify(ctx, detect.Token{Kind: KindServiceAccountToken, Value: "live"}); got.Status != detect.StatusActive || plainRequests.Load() != 1 {
		t.Fatalf("configured plain instance: %+v, %d requests", got, plainRequests.Load())
	}
}

func TestVerifyCloudToken(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.RequestURI())
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		_, body, _ := strings.Cut(auth, cloudPrefix)
		ct, _ := DecodeCloud(body)
		switch {
		case ct.Name == "dead":
			w.WriteHeader(http.StatusUnauthorized)
		case ct.Name == "narrow":
			w.WriteHeader(http.StatusForbidden)
		case ct.Name == "busy":
			w.WriteHeader(http.StatusTooManyRequests)
		case r.URL.Path == "/api/v1/tokens":
			_, _ = w.Write([]byte(`{"items":[{"id":"t-1","accessPolicyId":"ap-1","name":"other","expiresAt":null},{"id":"t-2","accessPolicyId":"ap-2","name":"` + ct.Name + `","expiresAt":"2027-01-31T00:00:00.000Z"}]}`))
		case r.URL.Path == "/api/v1/accesspolicies/ap-2":
			_, _ = w.Write([]byte(`{"id":"ap-2","name":"ci-metrics-writer","scopes":["metrics:write","logs:write"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	p := &Provider{CloudURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()
	mk := func(name string) detect.Token {
		v := cloudTokenValue(t, base64.StdEncoding, map[string]any{"o": "acme", "n": name, "k": "secret", "m": map[string]string{"r": "prod-eu-west-2"}})
		return detect.Token{Kind: KindCloudToken, Value: v}
	}
	got := p.Verify(ctx, mk("ci"))
	if got.Status != detect.StatusActive || got.Detail != "accepted by grafana.com for org acme, token ci, access policy ci-metrics-writer, scopes metrics:write logs:write" || got.Expires != "2027-01-31" {
		t.Fatalf("live: %+v", got)
	}
	if len(calls) != 2 || calls[0] != "/api/v1/tokens?region=prod-eu-west-2" || calls[1] != "/api/v1/accesspolicies/ap-2?region=prod-eu-west-2" {
		t.Fatalf("calls: %v", calls)
	}
	if got := p.Verify(ctx, mk("dead")); got.Status != detect.StatusRevoked {
		t.Fatalf("dead: %+v", got)
	}
	if got := p.Verify(ctx, mk("narrow")); got.Status != detect.StatusActive || !strings.Contains(got.Detail, "accesspolicies:read") {
		t.Fatalf("narrow: %+v", got)
	}
	if got := p.Verify(ctx, mk("busy")); got.Status != detect.StatusUnknown || got.Detail != "rate limited" {
		t.Fatalf("busy: %+v", got)
	}
	// A token whose name is not in the list is still live.
	calls = nil
	noRegion := cloudTokenValue(t, base64.StdEncoding, map[string]any{"o": "acme", "n": "unlisted", "k": "secret"})
	srvNoMatch := p.Verify(ctx, detect.Token{Kind: KindCloudToken, Value: noRegion})
	if srvNoMatch.Status != detect.StatusActive || !strings.Contains(srvNoMatch.Detail, "token unlisted") || calls[0] != "/api/v1/tokens" {
		t.Fatalf("unlisted without region: %+v, %v", srvNoMatch, calls)
	}
}
