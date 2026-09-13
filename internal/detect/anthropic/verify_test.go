package anthropic

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

// fake serves the model list, the organization and the Admin API for a
// fixed set of keys. Key values are made at run time; the server knows them
// by the roles the test assigns.
type fake struct {
	mu       sync.Mutex
	keys     map[string]string // value -> role: live, dead, forbidden, limited, broken, oauth-live, oauth-unsupported, admin-live
	admin    string            // the operator's admin key
	listed   []apiKey          // the organization's key list
	inactive []string          // ids set to inactive
	calls    []string          // method + path of every request
	pageSize int
}

func newFake(t *testing.T) (*fake, *Provider) {
	t.Helper()
	f := &fake{keys: map[string]string{}, pageSize: 2}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, &Provider{BaseURL: srv.URL, Client: srv.Client()}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("anthropic-version") != apiVersion || r.Header.Get("User-Agent") != detect.UserAgent {
		http.Error(w, "missing headers", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("x-api-key")
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if key == "" && bearer != "" && r.Header.Get("anthropic-beta") != oauthBeta {
		fail(w, http.StatusUnauthorized, "authentication_error", "OAuth authentication is currently not supported.")
		return
	}
	if key == "" {
		key = bearer
	}
	switch {
	case r.URL.Path == "/v1/models":
		f.models(w, f.keys[key])
	case r.URL.Path == "/v1/organizations/me":
		if f.keys[key] == "admin-live" {
			_, _ = fmt.Fprint(w, `{"id":"org-1","name":"Acme","type":"organization"}`)
		} else {
			fail(w, http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
		}
	case strings.HasPrefix(r.URL.Path, "/v1/organizations/api_keys"):
		if key != f.admin || f.admin == "" {
			fail(w, http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
			return
		}
		f.adminAPI(w, r)
	default:
		fail(w, http.StatusNotFound, "not_found_error", r.URL.Path)
	}
}

func (f *fake) models(w http.ResponseWriter, role string) {
	switch role {
	case "live", "oauth-live":
		_, _ = fmt.Fprint(w, `{"data":[{"id":"claude-sonnet-5","type":"model"}],"has_more":false}`)
	case "forbidden":
		fail(w, http.StatusForbidden, "permission_error", "not allowed")
	case "limited":
		fail(w, http.StatusTooManyRequests, "rate_limit_error", "slow down")
	case "broken":
		fail(w, http.StatusInternalServerError, "api_error", "oops")
	case "oauth-unsupported":
		fail(w, http.StatusUnauthorized, "authentication_error", "OAuth authentication is currently not supported.")
	default:
		fail(w, http.StatusUnauthorized, "authentication_error", "invalid x-api-key")
	}
}

func (f *fake) adminAPI(w http.ResponseWriter, r *http.Request) {
	if id := strings.TrimPrefix(r.URL.Path, "/v1/organizations/api_keys/"); r.Method == http.MethodPost && id != r.URL.Path {
		var req struct{ Status string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		for i := range f.listed {
			if f.listed[i].ID == id {
				f.listed[i].Status = req.Status
				f.inactive = append(f.inactive, id)
				_ = json.NewEncoder(w).Encode(f.listed[i])
				return
			}
		}
		fail(w, http.StatusNotFound, "not_found_error", "no such key")
		return
	}
	start := 0
	if after := r.URL.Query().Get("after_id"); after != "" {
		for i, k := range f.listed {
			if k.ID == after {
				start = i + 1
			}
		}
	}
	end := min(start+f.pageSize, len(f.listed))
	page := struct {
		Data    []apiKey `json:"data"`
		HasMore bool     `json:"has_more"`
		LastID  string   `json:"last_id"`
	}{Data: f.listed[start:end], HasMore: end < len(f.listed)}
	if end > start {
		page.LastID = f.listed[end-1].ID
	}
	_ = json.NewEncoder(w).Encode(page)
}

func fail(w http.ResponseWriter, status int, typ, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": typ, "message": msg}})
}

// hint redacts a key the way the Admin API lists it: the first three and
// last four characters of the body around an ellipsis.
func hint(key string) string {
	return key[:len(stem)+len("api03-")+3] + "…" + key[len(key)-4:]
}

// listed adds a key to the organization's list and returns it.
func (f *fake) list(id, name, workspace string, key string) apiKey {
	k := apiKey{ID: id, Name: name, Status: "active", Hint: hint(key)}
	k.Scope.Type, k.Scope.WorkspaceID = "workspace", workspace
	k.CreatedBy = &struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}{"user", "user_1"}
	f.listed = append(f.listed, k)
	return k
}

func TestVerify(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	roles := map[string]string{}
	for _, role := range []string{"live", "dead", "forbidden", "limited", "broken"} {
		roles[role] = newAPIKey()
		f.keys[roles[role]] = role
	}
	roles["oauth-live"], roles["oauth-unsupported"], roles["admin-live"], roles["admin-dead"] = oauth(), oauth(), newAdminKey(), newAdminKey()
	f.keys[roles["oauth-live"]], f.keys[roles["oauth-unsupported"]], f.keys[roles["admin-live"]] = "oauth-live", "oauth-unsupported", "admin-live"

	cases := []struct {
		role   string
		kind   detect.Kind
		status detect.VerifyStatus
		detail string
	}{
		{"live", KindAPIKey, detect.StatusActive, "accepted by the API"},
		{"dead", KindAPIKey, detect.StatusRevoked, ""},
		{"forbidden", KindAPIKey, detect.StatusActive, "accepted, but not allowed to list models"},
		{"limited", KindAPIKey, detect.StatusUnknown, "rate limited"},
		{"broken", KindAPIKey, detect.StatusUnknown, "HTTP 500 from /v1/models: oops"},
		{"oauth-live", KindOAuth, detect.StatusActive, "accepted by the API"},
		{"oauth-unsupported", KindOAuth, detect.StatusUnknown, "HTTP 401 from /v1/models: OAuth authentication is currently not supported."},
		{"admin-live", KindAdminKey, detect.StatusActive, "admin key for organization Acme"},
		{"admin-dead", KindAdminKey, detect.StatusRevoked, ""},
	}
	for _, c := range cases {
		got := p.Verify(ctx, detect.Token{Kind: c.kind, Value: roles[c.role]})
		if got.Status != c.status || got.Detail != c.detail {
			t.Errorf("%s: got %+v, want %s %q", c.role, got, c.status, c.detail)
		}
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindRefresh, Value: refresh()}); got.Status != detect.StatusUnverifiable {
		t.Errorf("refresh: %+v", got)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "api_keys") {
			t.Errorf("verification without an admin key touched the Admin API: %s", call)
		}
	}
}

func TestVerifyNamesTheKeyWithAnAdminKey(t *testing.T) {
	f, p := newFake(t)
	ctx := context.Background()
	live, other := newAPIKey(), newAPIKey()
	f.keys[live], f.keys[other] = "live", "live"
	f.admin = newAdminKey()
	p.AdminKey = f.admin
	f.list("apikey_0", "Unrelated", "wrkspc_0", newAPIKey())
	f.list("apikey_1", "CI deploy", "wrkspc_1", live)

	got := p.Verify(ctx, detect.Token{Kind: KindAPIKey, Value: live})
	if want := "accepted by the API, key CI deploy, workspace wrkspc_1, created by user user_1"; got.Status != detect.StatusActive || got.Detail != want {
		t.Errorf("named: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindAPIKey, Value: other}); got.Status != detect.StatusActive || got.Detail != "accepted by the API" {
		t.Errorf("foreign key: %+v", got)
	}
	lists := 0
	for _, call := range f.calls {
		if call == "GET /v1/organizations/api_keys" {
			lists++
		}
	}
	if lists != 1 {
		t.Errorf("the key list was fetched %d times, want once (one page of two keys)", lists)
	}
}
