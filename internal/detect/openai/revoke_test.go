package openai

import (
	"context"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestRevokeDeletesThroughTheAdminAPI(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	f.admin = newAdminKey()
	p.AdminKey = f.admin
	alpha, beta, gamma := project{ID: "proj_a", Name: "Alpha"}, project{ID: "proj_b", Name: "Beta"}, project{ID: "proj_c", Name: "Gamma"}
	leakedProject, leakedSvc, leakedAdmin := newProjectKey(), newServiceAccountKey(), newAdminKey()
	f.addProjectKey(alpha, "key_a1", "one", "user", "Ann", newProjectKey())
	f.addProjectKey(alpha, "key_a2", "two", "user", "Ann", newProjectKey())
	f.addProjectKey(alpha, "key_a3", "three", "user", "Bob", leakedProject)
	f.addProjectKey(beta, "key_b1", "svc", "service_account", "ci", leakedSvc)
	f.addProjectKey(gamma, "key_c1", "unrelated", "user", "Cy", newProjectKey())
	f.addAdmin("key_admin0", "Other", "Someone", newAdminKey())
	f.addAdmin("key_admin1", "Leaked", "Ops", leakedAdmin)
	f.addAdmin("key_admin2", "Operator", "Ops", f.admin)

	tokens := []detect.Token{{Kind: KindProject, Value: leakedProject}, {Kind: KindServiceAccount, Value: leakedSvc}, {Kind: KindAdmin, Value: leakedAdmin}}
	for _, tok := range tokens {
		if err := p.DryRunRevoke(ctx, tok); err != nil {
			t.Fatalf("dry run %s: %v", tok.Kind, err)
		}
	}
	if len(f.deleted) != 0 {
		t.Fatalf("dry run deleted %v", f.deleted)
	}
	if err := p.Revoke(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	want := "/v1/organization/projects/proj_a/api_keys/key_a3,/v1/organization/projects/proj_b/api_keys/key_b1,/v1/organization/admin_api_keys/key_admin1"
	if got := strings.Join(f.deleted, ","); got != want {
		t.Errorf("deleted\n%s\nwant\n%s", got, want)
	}
	counts := map[string]int{}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "GET ") {
			counts[call]++
		}
	}
	// Three projects in pages of two: two list calls; Alpha's three keys: two
	// pages; every list fetched once for three revocations and three dry runs.
	if counts["GET /v1/organization/projects"] != 2 || counts["GET /v1/organization/projects/proj_a/api_keys"] != 2 || counts["GET /v1/organization/projects/proj_b/api_keys"] != 1 || counts["GET /v1/organization/admin_api_keys"] != 2 {
		t.Errorf("list calls: %v", counts)
	}
}

func TestRevokeRefusals(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	f.admin = newAdminKey()
	p.AdminKey = f.admin
	twin := newProjectKey()
	proj := project{ID: "proj_a", Name: "Alpha"}
	f.addProjectKey(proj, "key_1", "twin a", "user", "Ann", twin)
	f.addProjectKey(proj, "key_2", "twin b", "user", "Ann", twin)
	listed := newProjectKey()
	f.addProjectKey(proj, "key_3", "listed", "user", "Ann", listed)

	cases := []struct {
		name string
		tok  detect.Token
		want string
	}{
		{"legacy", detect.Token{Kind: KindLegacy, Value: newLegacyKey()}, "legacy user keys are not listed by the Admin API"},
		{"foreign", detect.Token{Kind: KindProject, Value: newProjectKey()}, "not in this organization"},
		{"foreign admin", detect.Token{Kind: KindAdmin, Value: newAdminKey()}, "not in this organization"},
		{"ambiguous", detect.Token{Kind: KindProject, Value: twin}, "matches 2 redacted keys"},
	}
	for _, c := range cases {
		err := p.Revoke(ctx, []detect.Token{c.tok})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if len(f.deleted) != 0 {
		t.Errorf("refusals deleted %v", f.deleted)
	}

	p.AdminKey = ""
	err := p.Revoke(ctx, []detect.Token{{Kind: KindProject, Value: listed}})
	if err == nil || !strings.Contains(err.Error(), "set "+AdminKeyEnv) {
		t.Errorf("without admin key: %v", err)
	}

	p.AdminKey = newAdminKey() // not the organization's
	p.entries = nil
	err = p.Revoke(ctx, []detect.Token{{Kind: KindProject, Value: listed}})
	if err == nil || !strings.Contains(err.Error(), AdminKeyEnv+" is not accepted by OpenAI") {
		t.Errorf("rejected admin key: %v", err)
	}
}
