package registry

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/teemow/patty/internal/detect"
)

func TestRevokeHubPAT(t *testing.T) {
	hub := newFakeHub(t)
	hub.tokens["alice"] = []accessToken{{UUID: "u1", Label: "ci", Active: true, Scopes: []string{"repo:write"}, Token: hubPAT}}
	p := provider(nil, hub)
	ctx := context.Background()
	pat := detect.Token{Kind: KindHubPAT, Value: hubPAT, Secret: "alice"}

	if err := p.DryRunRevoke(ctx, pat); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(hub.patched) != 0 || !hub.tokens["alice"][0].Active {
		t.Fatal("the dry run must change nothing")
	}
	if err := p.Revoke(ctx, []detect.Token{pat}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if len(hub.patched) != 1 || hub.patched[0] != "u1" || hub.tokens["alice"][0].Active {
		t.Fatalf("token not deactivated: patched %v, %+v", hub.patched, hub.tokens["alice"])
	}
	if v := p.Verify(ctx, pat); v.Status != detect.StatusRevoked {
		t.Errorf("after revocation: %+v", v)
	}
	if err := p.Revoke(ctx, []detect.Token{pat}); err == nil || !strings.Contains(err.Error(), "already rejected") {
		t.Errorf("revoking a dead token: %v", err)
	}
}

func TestRevokeHubPATReadOnly(t *testing.T) {
	hub := newFakeHub(t)
	hub.tokens["alice"] = []accessToken{{UUID: "u1", Label: "pull-only", Active: true, Scopes: []string{"repo:public_read"}, Token: hubPAT}}
	p := provider(nil, hub)
	err := p.Revoke(context.Background(), []detect.Token{{Kind: KindHubPAT, Value: hubPAT, Secret: "alice"}})
	if err == nil || !strings.Contains(err.Error(), "read-only") || !strings.Contains(err.Error(), hubSecurityPage) {
		t.Fatalf("a read-only token cannot deactivate itself, got %v", err)
	}
	if len(hub.patched) != 0 {
		t.Fatal("nothing must be patched")
	}
}

func TestRevokeHubPATFindsItself(t *testing.T) {
	other := "dckr_" + "pat_" + strings.Repeat("Zz9", 9)
	stale := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	ctx := context.Background()
	pat := detect.Token{Kind: KindHubPAT, Value: hubPAT, Secret: "alice"}

	// Several active tokens, none listed with its value: the one just
	// used to log in is the one.
	hub := newFakeHub(t)
	hub.tokens["alice"] = []accessToken{
		{UUID: "u1", Label: "old", Active: true, Scopes: []string{"repo:write"}, Token: other, LastUsed: stale},
		{UUID: "u2", Label: "leaked", Active: true, Scopes: []string{"repo:write"}, Token: hubPAT, LastUsed: stale},
	}
	if err := provider(nil, hub).Revoke(ctx, []detect.Token{pat}); err != nil || len(hub.patched) != 1 || hub.patched[0] != "u2" {
		t.Errorf("match by recent use: err %v, patched %v", err, hub.patched)
	}

	// Two tokens used recently: ambiguous, nothing is touched.
	hub = newFakeHub(t)
	now := time.Now().UTC().Format(time.RFC3339)
	hub.tokens["alice"] = []accessToken{
		{UUID: "u1", Label: "a", Active: true, Scopes: []string{"repo:write"}, Token: other, LastUsed: now},
		{UUID: "u2", Label: "b", Active: true, Scopes: []string{"repo:write"}, Token: hubPAT, LastUsed: now},
	}
	if err := provider(nil, hub).Revoke(ctx, []detect.Token{pat}); err == nil || !strings.Contains(err.Error(), "cannot tell which") || len(hub.patched) != 0 {
		t.Errorf("ambiguous: err %v, patched %v", err, hub.patched)
	}

	// Listed with values (or hints): matched directly, however many.
	hub = newFakeHub(t)
	hub.listValues = true
	hub.tokens["alice"] = []accessToken{
		{UUID: "u1", Label: "a", Active: true, Scopes: []string{"repo:write"}, Token: other, LastUsed: now},
		{UUID: "u2", Label: "b", Active: true, Scopes: []string{"repo:write"}, Token: hubPAT, LastUsed: now},
	}
	if err := provider(nil, hub).Revoke(ctx, []detect.Token{pat}); err != nil || len(hub.patched) != 1 || hub.patched[0] != "u2" {
		t.Errorf("match by value: err %v, patched %v", err, hub.patched)
	}
}

func TestRevokeRefusesOtherKinds(t *testing.T) {
	p := provider(nil, nil)
	ctx := context.Background()
	for _, tok := range []detect.Token{
		{Kind: KindHubOAT, Value: hubOAT, Secret: "acme"},
		{Kind: KindQuayRobot, Value: robotTok, Secret: "acme+ci"},
		login("quay.io", "acme+ci", "pw"),
		login("example.azurecr.io", "admin", "pw"),
	} {
		if err := p.Revoke(ctx, []detect.Token{tok}); err == nil || !strings.Contains(err.Error(), "only Docker Hub personal access tokens") {
			t.Errorf("%s: %v", tok.Kind, err)
		}
	}
	if err := p.Revoke(ctx, []detect.Token{{Kind: KindHubPAT, Value: hubPAT}}); err == nil || !strings.Contains(err.Error(), "username not found") {
		t.Errorf("PAT without username: %v", err)
	}
	var _ detect.DryRunRevoker = p
}
