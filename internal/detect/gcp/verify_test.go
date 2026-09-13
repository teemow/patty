package gcp

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// call is one request the fake Google saw.
type call struct {
	path string
	form map[string]string
}

var now = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

// server fakes the token, tokeninfo, revoke and discovery endpoints on one
// host. The credential decides the answer: the service account's local
// part, a marker in a token's body, the fill of an API key.
func server(t *testing.T) (*Provider, func() []call) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls []call
	)
	fail := func(w http.ResponseWriter, status int, err, desc string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(oauthError{Error: err, Description: desc})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("User-Agent"), detect.UserAgent) {
			t.Errorf("User-Agent %q does not name patty", r.Header.Get("User-Agent"))
		}
		_ = r.ParseForm()
		c := call{path: r.URL.Path, form: map[string]string{}}
		for k := range r.Form {
			c.form[k] = r.Form.Get(k)
		}
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			if r.Method != http.MethodPost {
				t.Errorf("token requests are posted, got %s", r.Method)
			}
			switch c.form["grant_type"] {
			case jwtBearerGrant:
				tokenEndpoint(t, w, c.form["assertion"], srvURL(r), fail)
			case "refresh_token":
				refreshEndpoint(w, c.form, fail)
			default:
				fail(w, http.StatusBadRequest, "unsupported_grant_type", c.form["grant_type"])
			}
		case "/tokeninfo":
			tokeninfoEndpoint(w, c.form["access_token"], fail)
		case "/revoke":
			switch {
			case strings.Contains(c.form["token"], "dead"):
				fail(w, http.StatusBadRequest, "invalid_token", "Token expired or revoked")
			case strings.Contains(c.form["token"], "broken"):
				w.WriteHeader(http.StatusInternalServerError)
			default:
				_, _ = w.Write([]byte("{}"))
			}
		case "/discovery/v1/apis":
			discoveryEndpoint(w, r.URL.Query().Get("key"))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	p := New()
	p.TokenURL, p.TokenInfoURL, p.RevokeURL, p.DiscoveryURL = srv.URL+"/token", srv.URL+"/tokeninfo", srv.URL+"/revoke", srv.URL+"/discovery/v1/apis"
	p.Client = srv.Client()
	p.now = func() time.Time { return now }
	return p, func() []call {
		mu.Lock()
		defer mu.Unlock()
		return append([]call(nil), calls...)
	}
}

func srvURL(r *http.Request) string { return "http://" + r.Host + "/token" }

// tokenEndpoint checks the assertion the way Google does: three parts,
// RS256 over the first two with the account's key, the right audience,
// scope and lifetime; then answers by the account's name.
func tokenEndpoint(t *testing.T, w http.ResponseWriter, assertion, audience string, fail func(http.ResponseWriter, int, string, string)) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		fail(w, http.StatusBadRequest, "invalid_grant", "Invalid JWT")
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Errorf("signature is not base64url: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		fail(w, http.StatusBadRequest, "invalid_grant", "Invalid JWT Signature.")
		return
	}
	var claims struct {
		Iss, Scope, Aud string
		Iat, Exp        int64
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Errorf("claims do not parse: %v", err)
	}
	if claims.Aud != audience || claims.Scope != cloudPlatformScope || claims.Exp-claims.Iat != int64(assertionLifetime/time.Second) || claims.Iat != now.Unix() {
		t.Errorf("assertion claims %+v, want aud %s, scope %s, one minute from %d", claims, audience, cloudPlatformScope, now.Unix())
	}
	local, _, _ := strings.Cut(claims.Iss, "@")
	switch local {
	case "deleted-key":
		fail(w, http.StatusBadRequest, "invalid_grant", "Invalid JWT Signature.")
	case "deleted-account":
		fail(w, http.StatusBadRequest, "invalid_grant", "Invalid grant: account not found")
	case "disabled":
		fail(w, http.StatusBadRequest, "invalid_grant", "Invalid grant: account disabled")
	case "odd":
		fail(w, http.StatusBadRequest, "invalid_grant", "Invalid grant: something new")
	case "forbidden":
		fail(w, http.StatusForbidden, "access_denied", "Requested scope is not allowed")
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.minted", "expires_in": 3599, "token_type": "Bearer"})
	}
}

func refreshEndpoint(w http.ResponseWriter, form map[string]string, fail func(http.ResponseWriter, int, string, string)) {
	switch {
	case form["client_id"] == "" || form["client_secret"] == "":
		fail(w, http.StatusUnauthorized, "invalid_client", "Unauthorized")
	case strings.Contains(form["client_secret"], "wrong"):
		fail(w, http.StatusUnauthorized, "invalid_client", "The OAuth client was not found.")
	case strings.Contains(form["refresh_token"], "dead"):
		fail(w, http.StatusBadRequest, "invalid_grant", "Token has been expired or revoked.")
	case strings.Contains(form["refresh_token"], "broken"):
		w.WriteHeader(http.StatusInternalServerError)
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ya29.minted", "expires_in": 3599, "scope": "openid https://www.googleapis.com/auth/cloud-platform"})
	}
}

func tokeninfoEndpoint(w http.ResponseWriter, token string, fail func(http.ResponseWriter, int, string, string)) {
	switch {
	case strings.Contains(token, "dead"):
		fail(w, http.StatusBadRequest, "invalid_token", "Invalid Value")
	case strings.Contains(token, "broken"):
		w.WriteHeader(http.StatusInternalServerError)
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{
			"azp": clientID, "aud": clientID, "email": "jane@example.com", "expires_in": "1799",
			"scope": "openid https://www.googleapis.com/auth/cloud-platform",
		})
	}
}

func discoveryEndpoint(w http.ResponseWriter, key string) {
	answer := func(status int, code int, msg, st string) {
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":%q,"status":%q}}`, code, msg, st)
	}
	switch {
	case strings.HasPrefix(key, apiKeyPrefix+"dead"):
		answer(http.StatusBadRequest, 400, "API key not valid. Please pass a valid API key.", "INVALID_ARGUMENT")
	case strings.HasPrefix(key, apiKeyPrefix+"rest"):
		answer(http.StatusForbidden, 403, "Requests to this API discovery method are blocked.", "PERMISSION_DENIED")
	case strings.HasPrefix(key, apiKeyPrefix+"limit"):
		answer(http.StatusTooManyRequests, 429, "Quota exceeded", "RESOURCE_EXHAUSTED")
	default:
		_, _ = w.Write([]byte(`{"kind":"discovery#directoryList","items":[]}`))
	}
}

// serviceAccountToken is the finding for a key file whose token_uri does
// not point at Google, so nothing in these tests leaves the test server.
func serviceAccountToken(t *testing.T, extra map[string]string) detect.Token {
	t.Helper()
	fields := map[string]string{"token_uri": ""}
	for k, v := range extra {
		fields[k] = v
	}
	found := find([]byte(serviceAccountJSON(t, fields)))
	if len(found) != 1 {
		t.Fatalf("fixture yields %d tokens", len(found))
	}
	return detect.Token{Kind: found[0].Kind, Value: found[0].Value, Secret: found[0].Secret}
}

func TestVerifyServiceAccountKey(t *testing.T) {
	p, calls := server(t)
	// A token_uri that is not an https URL under googleapis.com is ignored
	// in favour of the provider's endpoint: a repository must not be able
	// to send patty anywhere.
	for _, uri := range []string{"", "https://evil.example.com/token", "http://oauth2.googleapis.com/token", "https://oauth2.googleapis.com.evil.example/token", "not a url"} {
		tok := serviceAccountToken(t, map[string]string{"token_uri": uri})
		v := p.Verify(context.Background(), tok)
		if v.Status != detect.StatusActive || v.Detail != "service account "+email+" in "+project {
			t.Errorf("token_uri %q: %+v", uri, v)
		}
	}
	for local, want := range map[string]detect.Verification{
		"deleted-key":     {Status: detect.StatusRevoked, Detail: "key deleted: the signature is no longer known to service account deleted-key@" + project + ".iam.gserviceaccount.com in " + project},
		"deleted-account": {Status: detect.StatusRevoked, Detail: "service account deleted-account@" + project + ".iam.gserviceaccount.com in " + project + " no longer exists"},
		"disabled":        {Status: detect.StatusRevoked, Detail: "service account disabled@" + project + ".iam.gserviceaccount.com in " + project + " is disabled: Invalid grant: account disabled"},
		"odd":             {Status: detect.StatusUnknown, Detail: "HTTP 400: invalid_grant (Invalid grant: something new)"},
		"forbidden":       {Status: detect.StatusUnknown, Detail: "HTTP 403: access_denied (Requested scope is not allowed)"},
	} {
		tok := serviceAccountToken(t, map[string]string{"client_email": local + "@" + project + ".iam.gserviceaccount.com"})
		if v := p.Verify(context.Background(), tok); v != want {
			t.Errorf("%s: got %+v, want %+v", local, v, want)
		}
	}
	for _, c := range calls() {
		if c.path != "/token" || c.form["grant_type"] != jwtBearerGrant || c.form["assertion"] == "" {
			t.Errorf("unexpected request %+v", c)
		}
		if strings.Contains(c.form["assertion"], "PRIVATE") {
			t.Error("the private key was sent")
		}
	}
}

func TestTokenURL(t *testing.T) {
	p := New()
	for uri, want := range map[string]string{
		"https://oauth2.googleapis.com/token":         "https://oauth2.googleapis.com/token",
		"https://sts.googleapis.com/v1/token":         "https://sts.googleapis.com/v1/token",
		"https://googleapis.com/token":                "https://googleapis.com/token",
		"":                                            p.TokenURL,
		"https://evil.example.com/token":              p.TokenURL,
		"http://oauth2.googleapis.com/token":          p.TokenURL,
		"https://oauth2.googleapis.com.example/token": p.TokenURL,
	} {
		if got := p.tokenURL(uri); got != want {
			t.Errorf("tokenURL(%q) = %q, want %q", uri, got, want)
		}
	}
}

func TestVerifyServiceAccountKeyMalformed(t *testing.T) {
	p, calls := server(t)
	for name, key := range map[string]string{
		"not pem": "not a key",
		"not rsa": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"no pem":  "",
		"ec key":  ecPEM(t),
	} {
		tok := detect.Token{Kind: KindServiceAccountKey, Value: email + "/" + keyID, Secret: credential{PrivateKey: key}.encode()}
		v := p.Verify(context.Background(), tok)
		if v.Status != detect.StatusUnverifiable || !strings.HasPrefix(v.Detail, "malformed key: ") {
			t.Errorf("%s: %+v", name, v)
		}
	}
	if len(calls()) != 0 {
		t.Errorf("a malformed key was sent somewhere: %+v", calls())
	}
}

func TestVerifyAccessToken(t *testing.T) {
	p, calls := server(t)
	live := detect.Token{Kind: KindAccessToken, Value: accessToken("Liv3")}
	v := p.Verify(context.Background(), live)
	want := detect.Verification{Status: detect.StatusActive, Detail: "account jane@example.com, scopes: openid, https://www.googleapis.com/auth/cloud-platform", ClientID: clientID, Expires: "2026-09-13 12:29 UTC"}
	if v != want {
		t.Errorf("live: got %+v, want %+v", v, want)
	}
	if v := p.Verify(context.Background(), detect.Token{Kind: KindAccessToken, Value: accessPrefix + strings.Repeat("dead", 25)}); v.Status != detect.StatusRevoked {
		t.Errorf("dead: %+v", v)
	}
	if v := p.Verify(context.Background(), detect.Token{Kind: KindAccessToken, Value: accessPrefix + strings.Repeat("broken", 20)}); v.Status != detect.StatusUnknown || v.Detail != "HTTP 500" {
		t.Errorf("broken: %+v", v)
	}
	for _, c := range calls() {
		if c.path != "/tokeninfo" || c.form["access_token"] == "" {
			t.Errorf("unexpected request %+v", c)
		}
	}
}

func TestVerifyRefreshToken(t *testing.T) {
	p, calls := server(t)
	bare := detect.Token{Kind: KindRefreshToken, Value: refreshToken("Bare")}
	if v := p.Verify(context.Background(), bare); v.Status != detect.StatusUnverifiable || !strings.Contains(v.Detail, "client id and secret") {
		t.Errorf("bare: %+v", v)
	}
	if len(calls()) != 0 {
		t.Errorf("a bare refresh token was sent somewhere: %+v", calls())
	}
	with := func(kind detect.Kind, refresh, secret string) detect.Token {
		return detect.Token{Kind: kind, Value: refresh, Secret: credential{ClientID: clientID, ClientSecret: secret}.encode()}
	}
	v := p.Verify(context.Background(), with(KindUserCredentials, refreshToken("Liv3"), "s3cret"))
	want := detect.Verification{Status: detect.StatusActive, Detail: "refresh token accepted for OAuth client 123456789012, scopes: openid, https://www.googleapis.com/auth/cloud-platform", ClientID: clientID}
	if v != want {
		t.Errorf("live: got %+v, want %+v", v, want)
	}
	// A bare refresh token that learnt its client from another occurrence
	// is checked the same way.
	if v := p.Verify(context.Background(), with(KindRefreshToken, refreshToken("Liv3"), "s3cret")); v.Status != detect.StatusActive {
		t.Errorf("bare kind with client: %+v", v)
	}
	if v := p.Verify(context.Background(), with(KindUserCredentials, refreshPrefix+strings.Repeat("dead", 15), "s3cret")); v.Status != detect.StatusRevoked || v.Detail != "expired or revoked: Token has been expired or revoked." {
		t.Errorf("dead: %+v", v)
	}
	if v := p.Verify(context.Background(), with(KindUserCredentials, refreshToken("Liv3"), "wrong")); v.Status != detect.StatusUnknown || !strings.Contains(v.Detail, "client secret found next to it is not accepted") {
		t.Errorf("wrong client: %+v", v)
	}
	if v := p.Verify(context.Background(), with(KindUserCredentials, refreshPrefix+strings.Repeat("broken", 10), "s3cret")); v.Status != detect.StatusUnknown {
		t.Errorf("broken: %+v", v)
	}
	for _, c := range calls() {
		if c.path != "/token" || c.form["grant_type"] != "refresh_token" {
			t.Errorf("unexpected request %+v", c)
		}
	}
}

func TestVerifyAPIKey(t *testing.T) {
	p, calls := server(t)
	for fill, want := range map[string]detect.Verification{
		"open0": {Status: detect.StatusActive, Detail: "unrestricted: accepted by the Discovery API"},
		"rest0": {Status: detect.StatusActive, Detail: "restricted: the key exists but may not call the Discovery API (Requests to this API discovery method are blocked.)"},
		"dead0": {Status: detect.StatusRevoked, Detail: "deleted or never valid"},
		"limit": {Status: detect.StatusUnknown, Detail: "HTTP 429: Quota exceeded"},
	} {
		tok := detect.Token{Kind: KindAPIKey, Value: apiKeyPrefix + strings.Repeat(fill, 7)}
		if v := p.Verify(context.Background(), tok); v != want {
			t.Errorf("%s: got %+v, want %+v", fill, v, want)
		}
	}
	for _, c := range calls() {
		if c.path != "/discovery/v1/apis" || !strings.HasPrefix(c.form["key"], apiKeyPrefix) {
			t.Errorf("unexpected request %+v", c)
		}
	}
}

func TestVerifyUnreachable(t *testing.T) {
	p, _ := server(t)
	p.TokenURL, p.TokenInfoURL, p.DiscoveryURL = "http://127.0.0.1:1/token", "http://127.0.0.1:1/tokeninfo", "http://127.0.0.1:1/apis"
	for _, tok := range []detect.Token{
		serviceAccountToken(t, nil),
		{Kind: KindAccessToken, Value: accessToken("Liv3")},
		{Kind: KindAPIKey, Value: apiKey("k")},
		{Kind: "gcp-something-else", Value: "x"},
	} {
		if v := p.Verify(context.Background(), tok); v.Status != detect.StatusUnknown {
			t.Errorf("%s: %+v", tok.Kind, v)
		}
	}
}
