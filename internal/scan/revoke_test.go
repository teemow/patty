package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestRevoke(t *testing.T) {
	var (
		mu      sync.Mutex
		revoked = map[string]bool{}
		posted  []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
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
			tok := r.Header.Get("Authorization")[len("token "):]
			if revoked[tok] {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"login":"patty"}`))
		}
	}))
	defer srv.Close()
	revoker := &detect.Revoker{BaseURL: srv.URL, Client: srv.Client()}
	verifier := &detect.Verifier{BaseURL: srv.URL, Client: srv.Client()}
	active := &detect.Verification{Status: detect.StatusActive, Detail: "user patty"}

	results := []Result{
		{Target: "a", Findings: []Finding{
			{Kind: detect.KindPAT, Fingerprint: "1", Token: "one", Verification: active},
			{Kind: detect.KindOAuth, Fingerprint: "2", Token: "slow", Verification: active},
			{Kind: detect.KindServerToServer, Fingerprint: "3", Token: "app", Verification: active},
			{Kind: detect.KindPAT, Fingerprint: "4", Token: "dead", Verification: &detect.Verification{Status: detect.StatusRevoked}},
		}},
		{Target: "b", Findings: []Finding{
			{Kind: detect.KindPAT, Fingerprint: "1", Token: "one", Verification: active},
		}},
	}
	cands := Revocable(results)
	if len(cands) != 2 || cands[0].Fingerprint != "2" || cands[1].Fingerprint != "1" { // sorted by kind
		t.Fatalf("Revocable = %+v", cands)
	}

	done, err := Revoke(context.Background(), results, cands, revoker, verifier)
	if err != nil || done != 1 {
		t.Fatalf("Revoke = %d, %v", done, err)
	}
	if len(posted) != 2 {
		t.Fatalf("posted %v", posted)
	}
	for _, r := range results {
		for _, f := range r.Findings {
			switch f.Fingerprint {
			case "1":
				if f.Revocation != RevocationDone || !f.Revoked() {
					t.Errorf("%s/1: %+v", r.Target, f)
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
	if _, err := Revoke(context.Background(), results, []Finding{{Kind: detect.KindServerToServer, Fingerprint: "3", Token: "app"}}, revoker, verifier); err == nil {
		t.Fatal("installation tokens must be refused before anything is posted")
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
