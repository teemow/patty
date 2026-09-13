package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func login(host, user, password string) detect.Token {
	return detect.Token{Kind: kindFor(host), Value: host + "/" + user, Secret: password}
}

func TestVerifyLoginTokenDance(t *testing.T) {
	reg := newFakeRegistry(t, false, map[string]string{"alice": "correct-horse", "forbidden": "battery"})
	p := provider(reg, nil)
	ctx := context.Background()

	if v := p.Verify(ctx, login(reg.host(), "alice", "correct-horse")); v.Status != detect.StatusActive || v.Detail != reg.host()+", user alice" {
		t.Errorf("live login: %+v", v)
	}
	if got := reg.requests(); len(got) != 2 || got[0] != "/v2/" || got[1] != "/token?service=fake-registry" {
		t.Errorf("a verification is one anonymous probe and one token request, got %v", got)
	}
	if v := p.Verify(ctx, login(reg.host(), "alice", "wrong")); v.Status != detect.StatusRevoked {
		t.Errorf("wrong password: %+v", v)
	}
	if v := p.Verify(ctx, login(reg.host(), "nobody", "x")); v.Status != detect.StatusRevoked {
		t.Errorf("unknown user: %+v", v)
	}
	if v := p.Verify(ctx, login(reg.host(), "forbidden", "battery")); v.Status != detect.StatusActive || !strings.Contains(v.Detail, "forbidden") {
		t.Errorf("a 403 is a live login that may not have a token: %+v", v)
	}
	if v := p.Verify(ctx, login(reg.host(), "alice", "")); v.Status != detect.StatusUnverifiable {
		t.Errorf("no password: %+v", v)
	}
}

func TestVerifyLoginBasicRegistry(t *testing.T) {
	reg := newFakeRegistry(t, true, map[string]string{"AWS": "ecr-token"})
	p := provider(reg, nil)
	ctx := context.Background()
	if v := p.Verify(ctx, login(reg.host(), "AWS", "ecr-token")); v.Status != detect.StatusActive {
		t.Errorf("Basic-only registry: %+v", v)
	}
	if got := reg.requests(); len(got) != 2 || got[0] != "/v2/" || got[1] != "/v2/" {
		t.Errorf("a Basic registry gets the login at /v2/ itself, got %v", got)
	}
	if v := p.Verify(ctx, login(reg.host(), "AWS", "expired")); v.Status != detect.StatusRevoked {
		t.Errorf("rejected Basic login: %+v", v)
	}
}

func TestVerifyLoginUnreachable(t *testing.T) {
	reg := newFakeRegistry(t, false, nil)
	host := reg.host()
	reg.Close()
	p := provider(nil, nil)
	if v := p.Verify(context.Background(), login(host, "alice", "pw")); v.Status != detect.StatusUnknown || v.Detail == "" {
		t.Errorf("unreachable registry must be unknown with the error, got %+v", v)
	}
}

func TestVerifyDockerHub(t *testing.T) {
	hub := newFakeHub(t)
	hub.passwords["alice"] = "hunter2hunter2"
	hub.tokens["bob"] = []accessToken{{UUID: "u1", Label: "ci", Active: true, Scopes: []string{"repo:read"}, Token: hubPAT}}
	p := provider(nil, hub)
	ctx := context.Background()

	if v := p.Verify(ctx, login("index.docker.io", "alice", "hunter2hunter2")); v.Status != detect.StatusActive || v.Detail != "Docker Hub account alice" {
		t.Errorf("hub login: %+v", v)
	}
	if v := p.Verify(ctx, login("docker.io", "alice", "nope")); v.Status != detect.StatusRevoked {
		t.Errorf("hub login with a wrong password: %+v", v)
	}
	pat := detect.Token{Kind: KindHubPAT, Value: hubPAT, Secret: "bob"}
	if v := p.Verify(ctx, pat); v.Status != detect.StatusActive || v.Detail != "Docker Hub account bob" {
		t.Errorf("PAT with username: %+v", v)
	}
	pat.Secret = ""
	if v := p.Verify(ctx, pat); v.Status != detect.StatusUnverifiable || !strings.Contains(v.Detail, "username") {
		t.Errorf("PAT without username: %+v", v)
	}
	hub.tokens["bob"][0].Active = false
	pat.Secret = "bob"
	if v := p.Verify(ctx, pat); v.Status != detect.StatusRevoked {
		t.Errorf("deactivated PAT: %+v", v)
	}
}

func TestVerifyQuayTokens(t *testing.T) {
	reg := newFakeRegistry(t, false, map[string]string{"acme+ci": robotTok})
	p := provider(reg, nil)
	ctx := context.Background()
	robot := detect.Token{Kind: KindQuayRobot, Value: robotTok, Secret: "acme+ci"}
	if v := p.Verify(ctx, robot); v.Status != detect.StatusActive || v.Detail != reg.host()+", user acme+ci" {
		t.Errorf("robot token: %+v", v)
	}
	robot.Secret = "acme+other"
	if v := p.Verify(ctx, robot); v.Status != detect.StatusRevoked {
		t.Errorf("robot token with another robot's name: %+v", v)
	}
	// The Quay API is not part of the fake registry, so an OAuth token
	// gets a 404 and is unknown rather than anything definite.
	if v := p.Verify(ctx, detect.Token{Kind: KindQuayOAuth, Value: oauthTok}); v.Status != detect.StatusUnknown {
		t.Errorf("OAuth token against a registry without the API: %+v", v)
	}
}

func TestParseChallenge(t *testing.T) {
	scheme, params := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:a/b:pull,push"`)
	if scheme != "Bearer" || params["realm"] != "https://auth.docker.io/token" || params["service"] != "registry.docker.io" || params["scope"] != "repository:a/b:pull,push" {
		t.Errorf("bearer challenge: %s %v", scheme, params)
	}
	if scheme, params := parseChallenge(`Basic realm=fake`); scheme != "Basic" || params["realm"] != "fake" {
		t.Errorf("basic challenge: %s %v", scheme, params)
	}
	if scheme, params := parseChallenge(""); scheme != "" || len(params) != 0 {
		t.Errorf("empty challenge: %q %v", scheme, params)
	}
}
