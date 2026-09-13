package oci

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// fakeRegistry speaks the token dance of an OCI registry: /v2/ challenges
// anonymous requests with a Bearer realm (or Basic, when basicOnly), and
// the realm hands out a token for the logins it knows. The username
// decides the answer: "forbidden" logs in but may not have a token.
type fakeRegistry struct {
	*httptest.Server
	basicOnly bool
	// logins maps username to password.
	logins map[string]string
	mu     sync.Mutex
	// paths records every request path with its query, in order.
	paths []string
}

func newFakeRegistry(t *testing.T, basicOnly bool, logins map[string]string) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{basicOnly: basicOnly, logins: logins}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// host is what a config would name the registry as.
func (f *fakeRegistry) host() string { return strings.TrimPrefix(f.URL, "http://") }

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.RequestURI())
	f.mu.Unlock()
	if r.Header.Get("User-Agent") != detect.UserAgent {
		http.Error(w, "who are you", http.StatusBadRequest)
		return
	}
	user, pass, ok := r.BasicAuth()
	switch r.URL.Path {
	case "/v2/":
		switch {
		case !ok && f.basicOnly:
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			w.WriteHeader(http.StatusUnauthorized)
		case !ok:
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+f.URL+`/token",service="fake-registry",other="a,b"`)
			w.WriteHeader(http.StatusUnauthorized)
		case !f.basicOnly:
			http.Error(w, "use the token endpoint", http.StatusBadRequest)
		default:
			f.answer(w, user, pass, false)
		}
	case "/token":
		if r.URL.Query().Get("service") != "fake-registry" || r.URL.Query().Has("scope") {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		f.answer(w, user, pass, true)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeRegistry) answer(w http.ResponseWriter, user, pass string, token bool) {
	switch {
	case f.logins[user] == "" || f.logins[user] != pass:
		w.WriteHeader(http.StatusUnauthorized)
	case user == "forbidden":
		w.WriteHeader(http.StatusForbidden)
	case token:
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "opaque"})
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (f *fakeRegistry) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

// fakeHub is hub.docker.com: a login endpoint that answers with a JWT and
// the access-token list and edit endpoints behind that JWT.
type fakeHub struct {
	*httptest.Server
	mu sync.Mutex
	// passwords maps account to its password.
	passwords map[string]string
	// tokens maps account to its personal access tokens; a token's Token
	// field holds its value, which is how the login endpoint checks it and
	// which the list endpoint hides unless listValues is set.
	tokens     map[string][]accessToken
	listValues bool
	patched    []string
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	f := &fakeHub{passwords: map[string]string{}, tokens: map[string][]accessToken{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// mintJWT mints a token whose payload names the account, unsigned: the
// provider reads the claim, it does not verify the signature.
func mintJWT(account string) string {
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return enc(map[string]string{"alg": "none"}) + "." + enc(map[string]string{"username": account}) + ".sig"
}

func (f *fakeHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == hubLoginPath:
		var login struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&login)
		if f.passwords[login.Username] == login.Password && login.Password != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"token": mintJWT(login.Username)})
			return
		}
		for i, t := range f.tokens[login.Username] {
			if t.Active && t.Token == login.Password {
				f.tokens[login.Username][i].LastUsed = time.Now().UTC().Format(time.RFC3339)
				_ = json.NewEncoder(w).Encode(map[string]string{"token": mintJWT(login.Username)})
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Incorrect authentication credentials"})
	case strings.HasPrefix(r.URL.Path, accessTokensPath):
		account := jwtClaim(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "username")
		if account == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		list := f.tokens[account]
		switch r.Method {
		case http.MethodGet:
			shown := make([]accessToken, len(list))
			for i, t := range list {
				shown[i] = t
				if !f.listValues {
					shown[i].Token = ""
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"count": len(shown), "results": shown})
		case http.MethodPatch:
			uuid := strings.TrimPrefix(r.URL.Path, accessTokensPath+"/")
			var body struct {
				Active bool `json:"is_active"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for i, t := range list {
				if t.UUID == uuid {
					list[i].Active = body.Active
					f.patched = append(f.patched, uuid)
					_ = json.NewEncoder(w).Encode(list[i])
					return
				}
			}
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}

// provider returns a Provider aimed at the fakes; nil fakes leave the
// public URLs in place, which no test reaches.
func provider(reg *fakeRegistry, hub *fakeHub) *Provider {
	p := New()
	p.Scheme = "http"
	p.Client = &http.Client{Timeout: 5 * time.Second}
	if reg != nil {
		p.QuayHost = reg.host()
	}
	if hub != nil {
		p.HubURL = hub.URL
	}
	return p
}
