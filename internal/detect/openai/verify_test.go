package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// fake serves the model list and the Admin API for a fixed set of keys.
// Key values are made at run time; the server knows them by role.
type fake struct {
	mu       sync.Mutex
	keys     map[string]string // value -> role: live, dead, limited, broken, denied
	admin    string            // the operator's admin key
	adminOK  []adminKey        // the organization's admin key list
	projects []project
	byProj   map[string][]projectKey
	deleted  []string // paths of deleted keys
	calls    []string
	pageSize int
}

func newFake(t *testing.T) (*fake, *Provider) {
	t.Helper()
	f := &fake{keys: map[string]string{}, byProj: map[string][]projectKey{}, pageSize: 2}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &Provider{BaseURL: srv.URL, Client: srv.Client()}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if r.Header.Get("User-Agent") != detect.UserAgent {
		http.Error(w, "missing user agent", http.StatusBadRequest)
		return
	}
	switch {
	case r.URL.Path == "/v1/models":
		f.models(w, f.keys[key])
	case strings.HasPrefix(r.URL.Path, "/v1/organization/"):
		if key != f.admin || f.admin == "" {
			fail(w, http.StatusUnauthorized, "invalid_api_key", "Incorrect API key provided")
			return
		}
		f.adminAPI(w, r)
	default:
		fail(w, http.StatusNotFound, "not_found", r.URL.Path)
	}
}

func (f *fake) models(w http.ResponseWriter, role string) {
	switch role {
	case "live":
		w.Header().Set("openai-organization", "acme")
		w.Header().Set("openai-project", "proj_1")
		_, _ = fmt.Fprint(w, `{"object":"list","data":[{"id":"gpt-5","object":"model"}]}`)
	case "bare":
		_, _ = fmt.Fprint(w, `{"object":"list","data":[]}`)
	case "limited":
		fail(w, http.StatusTooManyRequests, "insufficient_quota", "You exceeded your current quota")
	case "broken":
		fail(w, http.StatusInternalServerError, "server_error", "oops")
	case "denied":
		fail(w, http.StatusUnauthorized, "", "You must be a member of an organization to use the API")
	default:
		fail(w, http.StatusUnauthorized, "invalid_api_key", "Incorrect API key provided")
	}
}

func (f *fake) adminAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/organization/")
	if r.Method == http.MethodDelete {
		f.deleted = append(f.deleted, r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": path[strings.LastIndex(path, "/")+1:], "deleted": true})
		return
	}
	parts := strings.Split(path, "/")
	switch {
	case path == "admin_api_keys":
		f.page(w, r, len(f.adminOK), func(i int) (string, any) { return f.adminOK[i].ID, f.adminOK[i] })
	case path == "projects":
		if r.URL.Query().Get("include_archived") != "true" {
			http.Error(w, "archived projects must be included", http.StatusBadRequest)
			return
		}
		f.page(w, r, len(f.projects), func(i int) (string, any) { return f.projects[i].ID, f.projects[i] })
	case len(parts) == 3 && parts[0] == "projects" && parts[2] == "api_keys":
		if r.URL.Query().Get("owner_project_access") != "any" {
			http.Error(w, "every key must be listed", http.StatusBadRequest)
			return
		}
		keys := f.byProj[parts[1]]
		f.page(w, r, len(keys), func(i int) (string, any) { return keys[i].ID, keys[i] })
	default:
		fail(w, http.StatusNotFound, "not_found", r.URL.Path)
	}
}

// page answers one page of a list of n items, pageSize at a time.
func (f *fake) page(w http.ResponseWriter, r *http.Request, n int, item func(int) (string, any)) {
	if r.URL.Query().Get("limit") != fmt.Sprint(listLimit) {
		http.Error(w, "limit", http.StatusBadRequest)
		return
	}
	start := 0
	if after := r.URL.Query().Get("after"); after != "" {
		for i := 0; i < n; i++ {
			if id, _ := item(i); id == after {
				start = i + 1
			}
		}
	}
	end := min(start+f.pageSize, n)
	out := map[string]any{"object": "list", "has_more": end < n}
	data := []any{}
	for i := start; i < end; i++ {
		id, v := item(i)
		data = append(data, v)
		out["last_id"] = id
	}
	out["data"] = data
	_ = json.NewEncoder(w).Encode(out)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"type": "invalid_request_error", "code": code, "message": msg, "param": nil}})
}

// hint redacts a key the way the Admin API lists it.
func hint(k string) string {
	return k[:6] + "..." + k[len(k)-4:]
}

func (f *fake) addAdmin(id, name, owner, k string) {
	a := adminKey{ID: id, Name: name, Hint: hint(k)}
	a.Owner.Name = owner
	f.adminOK = append(f.adminOK, a)
}

func (f *fake) addProjectKey(proj project, id, name, ownerType, owner, k string) {
	pk := projectKey{ID: id, Name: name, Hint: hint(k)}
	pk.Owner.Type = ownerType
	if ownerType == "user" {
		pk.Owner.User.Name = owner
	} else {
		pk.Owner.ServiceAccount.Name = owner
	}
	if _, ok := f.byProj[proj.ID]; !ok {
		f.projects = append(f.projects, proj)
	}
	f.byProj[proj.ID] = append(f.byProj[proj.ID], pk)
}

func TestVerify(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	roles := map[string]string{}
	for _, role := range []string{"live", "bare", "dead", "limited", "broken", "denied"} {
		roles[role] = newProjectKey()
		f.keys[roles[role]] = role
	}
	cases := []struct {
		role   string
		status detect.VerifyStatus
		detail string
	}{
		{"live", detect.StatusActive, "organization acme, project proj_1"},
		{"bare", detect.StatusActive, "accepted by the API"},
		{"dead", detect.StatusRevoked, ""},
		{"limited", detect.StatusUnknown, "rate limited, or the key's quota is exhausted; OpenAI answers both alike, so the key may well be live"},
		{"broken", detect.StatusUnknown, "HTTP 500 from /v1/models: oops"},
		{"denied", detect.StatusUnknown, "HTTP 401 from /v1/models: You must be a member of an organization to use the API"},
	}
	for _, c := range cases {
		got := p.Verify(ctx, detect.Token{Kind: KindProject, Value: roles[c.role]})
		if got.Status != c.status || got.Detail != c.detail {
			t.Errorf("%s: got %+v, want %s %q", c.role, got, c.status, c.detail)
		}
	}
	legacyKey := newLegacyKey()
	f.keys[legacyKey] = "bare"
	if got := p.Verify(ctx, detect.Token{Kind: KindLegacy, Value: legacyKey}); got.Status != detect.StatusActive {
		t.Errorf("legacy: %+v", got)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "/organization/") {
			t.Errorf("verification without an admin key touched the Admin API: %s", call)
		}
	}
}

func TestVerifyAdminKeyNamesItself(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	f.admin = newAdminKey()
	f.addAdmin("key_0", "Other", "Someone", newAdminKey())
	f.addAdmin("key_1", "Audit", "Ops bot", f.admin)

	if got := p.Verify(ctx, detect.Token{Kind: KindAdmin, Value: f.admin}); got.Status != detect.StatusActive || got.Detail != "admin key Audit, owned by Ops bot" {
		t.Errorf("admin: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindAdmin, Value: newAdminKey()}); got.Status != detect.StatusRevoked {
		t.Errorf("dead admin: %+v", got)
	}
	if p.entries != nil {
		t.Error("verifying an admin key with itself must not populate the operator's inventory")
	}
}

func TestVerifyNamesTheKeyWithAnAdminKey(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	live, foreign := newProjectKey(), newProjectKey()
	f.keys[live], f.keys[foreign] = "bare", "bare"
	f.admin = newAdminKey()
	p.AdminKey = f.admin
	f.addProjectKey(project{ID: "proj_a", Name: "Alpha"}, "key_a", "unrelated", "user", "Someone", newProjectKey())
	f.addProjectKey(project{ID: "proj_b", Name: "Beta"}, "key_b", "deploy", "service_account", "ci", live)

	if got := p.Verify(ctx, detect.Token{Kind: KindProject, Value: live}); got.Detail != "accepted by the API, key deploy in project Beta, owned by service account ci" {
		t.Errorf("named: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindProject, Value: foreign}); got.Detail != "accepted by the API" {
		t.Errorf("foreign: %+v", got)
	}
	lists := 0
	for _, call := range f.calls {
		if call == "GET /v1/organization/projects" {
			lists++
		}
	}
	if lists != 1 {
		t.Errorf("projects were listed %d times, want once", lists)
	}
}
