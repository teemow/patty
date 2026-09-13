package anthropic

import (
	"context"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestRevokeDeactivatesThroughTheAdminAPI(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	f.admin = newAdminKey()
	p.AdminKey = f.admin
	keys := []string{newAPIKey(), newAPIKey(), newAPIKey(), newAPIKey(), newAPIKey()}
	for i, k := range keys {
		f.keys[k] = "live"
		f.list("apikey_"+string(rune('a'+i)), "key "+string(rune('a'+i)), "wrkspc_1", k)
	}
	leaked := []detect.Token{{Kind: KindAPIKey, Value: keys[0]}, {Kind: KindAPIKey, Value: keys[4]}}

	if err := p.DryRunRevoke(ctx, leaked[0]); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(f.inactive) != 0 {
		t.Fatalf("dry run deactivated %v", f.inactive)
	}
	if err := p.Revoke(ctx, leaked); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.inactive, ",") != "apikey_a,apikey_e" {
		t.Errorf("deactivated %v", f.inactive)
	}
	pages := 0
	for _, call := range f.calls {
		if call == "GET /v1/organizations/api_keys" {
			pages++
		}
	}
	if pages != 3 {
		t.Errorf("five keys in pages of two should take 3 list calls, once; got %d", pages)
	}
	for _, id := range f.inactive {
		for _, k := range f.listed {
			if k.ID == id && k.Status != "inactive" {
				t.Errorf("%s is %s", id, k.Status)
			}
		}
	}
}

func TestRevokeRefusals(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	f.admin = newAdminKey()
	p.AdminKey = f.admin
	listed := newAPIKey()
	f.list("apikey_1", "one", "", listed)
	twin := newAPIKey()
	twinHint := hint(twin)
	f.list("apikey_2", "twin a", "", twin)
	f.listed[len(f.listed)-1].Hint = twinHint
	f.list("apikey_3", "twin b", "", twin)

	cases := []struct {
		name string
		tok  detect.Token
		want string
	}{
		{"admin key", detect.Token{Kind: KindAdminKey, Value: newAdminKey()}, "admin keys cannot be deactivated through the API"},
		{"oauth", detect.Token{Kind: KindOAuth, Value: oauth()}, "OAuth tokens cannot be revoked through the API"},
		{"refresh", detect.Token{Kind: KindRefresh, Value: refresh()}, "OAuth tokens cannot be revoked through the API"},
		{"foreign", detect.Token{Kind: KindAPIKey, Value: newAPIKey()}, "not in this organization"},
		{"ambiguous", detect.Token{Kind: KindAPIKey, Value: twin}, "matches the hints of 2 keys"},
	}
	for _, c := range cases {
		err := p.Revoke(ctx, []detect.Token{c.tok})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if len(f.inactive) != 0 {
		t.Errorf("refusals deactivated %v", f.inactive)
	}

	p.AdminKey = ""
	err := p.Revoke(ctx, []detect.Token{{Kind: KindAPIKey, Value: listed}})
	if err == nil || !strings.Contains(err.Error(), "set "+AdminKeyEnv) {
		t.Errorf("without admin key: %v", err)
	}

	p.AdminKey = newAdminKey() // not the organization's
	p.keys = nil
	err = p.Revoke(ctx, []detect.Token{{Kind: KindAPIKey, Value: listed}})
	if err == nil || !strings.Contains(err.Error(), AdminKeyEnv+" is not accepted by Anthropic") {
		t.Errorf("rejected admin key: %v", err)
	}
}

func TestHintMatches(t *testing.T) {
	key := newAPIKey()
	for h, want := range map[string]bool{
		hint(key): true,
		strings.ReplaceAll(hint(key), "…", "..."): true,
		hint(newAPIKey()): false,
		key[:20]:          false,
		key[:20] + "…":    false,
		"":                false,
	} {
		if got := detect.HintMatches(h, key); got != want {
			t.Errorf("HintMatches(%q) = %v", h, got)
		}
	}
}
