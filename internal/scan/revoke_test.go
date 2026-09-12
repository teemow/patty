package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/aws"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/slack"
)

// fakeAPIs serves GitHub's revocation endpoint and Slack's auth.test and
// auth.revoke from one server; every token but "slow" dies when revoked.
func fakeAPIs(t *testing.T) (*detect.Registry, *[]string) {
	t.Helper()
	var (
		mu      sync.Mutex
		revoked = map[string]bool{}
		posted  []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch r.URL.Path {
		case "/credentials/revoke":
			var body struct{ Credentials []string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, c := range body.Credentials {
				posted = append(posted, c)
				if c != "slow" {
					revoked[c] = true
				}
			}
			w.WriteHeader(http.StatusAccepted)
		case "/user":
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "token ")
			if revoked[tok] {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"login":"patty"}`))
		case "/api/auth.revoke":
			posted = append(posted, bearer)
			revoked[bearer] = true
			_, _ = w.Write([]byte(`{"ok":true,"revoked":true}`))
		case "/api/auth.test":
			if revoked[bearer] {
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"team":"acme","user":"bot","bot_id":"B1"}`))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	gh := &github.Provider{BaseURL: srv.URL, Client: srv.Client()}
	sl := &slack.Provider{APIURL: srv.URL + "/api", HooksURL: srv.URL, Client: srv.Client()}
	return detect.NewRegistry(gh, sl), &posted
}

func TestRevoke(t *testing.T) {
	registry, posted := fakeAPIs(t)
	active := &detect.Verification{Status: detect.StatusActive, Detail: "user patty"}

	results := []Result{
		{Target: "a", Findings: []Finding{
			{Kind: github.KindPAT, Fingerprint: "1", Token: "one", Verification: active},
			{Kind: github.KindOAuth, Fingerprint: "2", Token: "slow", Verification: active},
			{Kind: github.KindServerToServer, Fingerprint: "3", Token: "app", Verification: active},
			{Kind: github.KindPAT, Fingerprint: "4", Token: "dead", Verification: &detect.Verification{Status: detect.StatusRevoked}},
			{Kind: slack.KindBot, Fingerprint: "5", Token: "bot", Verification: active},
			{Kind: slack.KindWebhook, Fingerprint: "6", Token: "hook", Verification: active},
		}},
		{Target: "b", Findings: []Finding{
			{Kind: github.KindPAT, Fingerprint: "1", Token: "one", Verification: active},
		}},
	}
	cands := Revocable(results, registry)
	if len(cands) != 3 || cands[0].Fingerprint != "2" || cands[1].Fingerprint != "1" || cands[2].Fingerprint != "5" { // sorted by kind
		t.Fatalf("Revocable = %+v", cands)
	}

	done, err := Revoke(context.Background(), results, cands, registry)
	if err != nil || done != 2 {
		t.Fatalf("Revoke = %d, %v", done, err)
	}
	if len(*posted) != 3 {
		t.Fatalf("posted %v", *posted)
	}
	for _, r := range results {
		for _, f := range r.Findings {
			switch f.Fingerprint {
			case "1", "5":
				if f.Revocation != RevocationDone || !f.Revoked() {
					t.Errorf("%s/%s: %+v", r.Target, f.Fingerprint, f)
				}
			case "2":
				if f.Revocation != RevocationPending || !f.Active() {
					t.Errorf("2: %+v", f)
				}
			default:
				if f.Revocation != "" {
					t.Errorf("%s untouched: %+v", f.Fingerprint, f)
				}
			}
		}
	}
	for _, f := range []Finding{
		{Kind: github.KindServerToServer, Fingerprint: "3", Token: "app"},
		{Kind: slack.KindWebhook, Fingerprint: "6", Token: "hook"},
		{Kind: "unknown-kind", Fingerprint: "7", Token: "x"},
	} {
		if _, err := Revoke(context.Background(), results, []Finding{f}, registry); err == nil {
			t.Errorf("%s must be refused before anything is posted", f.Kind)
		}
	}
	if len(*posted) != 3 {
		t.Fatalf("refused kinds must not reach the API: %v", *posted)
	}
}

func TestMergeAndAnnotateLocal(t *testing.T) {
	results := []Result{
		{Findings: []Finding{{Fingerprint: "x", Occurrences: 1, Locations: []Location{{Repo: "a"}}}}},
		{Findings: []Finding{{Fingerprint: "x", Occurrences: 2, Locations: []Location{{Repo: "b"}}, Revocation: RevocationDone}}},
	}
	AnnotateLocal(results, map[string][]string{"x": {"~/.config/hub"}})
	m := Merge(results)
	if len(m) != 1 || m[0].Occurrences != 3 || len(m[0].Locations) != 2 || m[0].Revocation != RevocationDone || len(m[0].Local) != 1 {
		t.Fatalf("Merge = %+v", m)
	}
}

func TestMergeCompletesKeyPairs(t *testing.T) {
	// The same key id, once alone and once with its secret: the merged
	// finding is the pair, whichever came first.
	alone := Finding{Kind: aws.KindAccessKey, Fingerprint: "k", Token: "id", Attribution: "account 1, key id only"}
	paired := Finding{Kind: aws.KindAccessKey, Fingerprint: "k", Token: "id", Secret: "s", Attribution: "account 1, key pair"}
	for _, order := range [][]Finding{{alone, paired}, {paired, alone}} {
		m := Merge([]Result{{Findings: order[:1]}, {Findings: order[1:]}})
		if len(m) != 1 || m[0].Secret != "s" || m[0].Attribution != "account 1, key pair" {
			t.Fatalf("Merge = %+v", m)
		}
		if tok := m[0].Detected(); tok.Kind != aws.KindAccessKey || tok.Value != "id" || tok.Secret != "s" {
			t.Fatalf("Detected = %+v", tok)
		}
	}
}
