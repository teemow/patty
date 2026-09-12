package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRewritesPaginatesAndSkipsZeroSHAs(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/repos/o/r/activity" {
			http.NotFound(w, r)
			return
		}
		typ, after := r.URL.Query().Get("activity_type"), r.URL.Query().Get("after")
		var body []map[string]any
		switch {
		case typ == "force_push" && after == "":
			w.Header().Set("Link", `<`+"http://x/repos/o/r/activity?after=CURSOR"+`>; rel="next"`)
			body = []map[string]any{
				{"before": "aaaa", "after": "bbbb", "ref": "refs/heads/main", "timestamp": "2026-09-10T09:48:33Z", "activity_type": "force_push", "actor": map[string]any{"login": "patty"}},
				{"before": "0000000000000000000000000000000000000000", "after": "cccc", "ref": "refs/heads/new", "timestamp": "2026-09-10T09:48:33Z", "activity_type": "force_push"},
			}
		case typ == "force_push" && after == "CURSOR":
			body = []map[string]any{{"before": "dddd", "after": "eeee", "ref": "refs/heads/dev", "timestamp": "2026-09-01T00:00:00Z", "activity_type": "force_push"}}
		case typ == "branch_deletion":
			body = []map[string]any{{"before": "ffff", "after": "0000000000000000000000000000000000000000", "ref": "refs/heads/gone", "timestamp": "2026-08-01T00:00:00Z", "activity_type": "branch_deletion"}}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	c := NewClientWithBaseURL(srv.URL)
	got, err := c.Rewrites(context.Background(), "o", "r", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Before != "aaaa" || got[0].Actor != "patty" || got[1].Before != "dddd" || got[2].Before != "ffff" || got[2].After != "" {
		t.Fatalf("unexpected rewrites %+v", got)
	}
	if calls != 3 {
		t.Fatalf("expected 3 API calls, got %d", calls)
	}
	if d := got[0].Describe(); d != "force-pushed away from main on 2026-09-10 by patty" {
		t.Fatalf("Describe = %q", d)
	}
	if d := got[2].Describe(); d != "deleted with gone on 2026-08-01" {
		t.Fatalf("Describe = %q", d)
	}
}

func TestListReposFiltersForksAndArchived(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/acme":
			_, _ = w.Write([]byte(`{"login":"acme","type":"Organization"}`))
		case "/orgs/acme/repos":
			_, _ = w.Write([]byte(`[
				{"full_name":"acme/app","size":120,"default_branch":"main"},
				{"full_name":"acme/fork","size":5,"fork":true,"default_branch":"main"},
				{"full_name":"acme/old","size":9,"archived":true,"default_branch":"main"},
				{"full_name":"acme/empty","size":0}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClientWithBaseURL(srv.URL)

	got, err := c.ListRepos(context.Background(), "acme", ListOptions{})
	if err != nil || len(got) != 1 || got[0].FullName() != "acme/app" || got[0].SizeKB != 120 {
		t.Fatalf("default filter: %+v %v", got, err)
	}
	got, err = c.ListRepos(context.Background(), "acme", ListOptions{IncludeForks: true, IncludeArchived: true})
	if err != nil || len(got) != 3 {
		t.Fatalf("include all: %+v %v", got, err)
	}
	if got[0].CloneURL() != "https://github.com/acme/app.git" {
		t.Fatalf("CloneURL = %q", got[0].CloneURL())
	}
}
