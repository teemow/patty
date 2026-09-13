package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// call is one request the fake Azure saw.
type call struct {
	method, host, path string
	form               map[string]string
	auth               string
}

// rewrite sends every request to the test server, whatever host it names,
// and tells the server which host that was: storage requests carry the
// account in the host name, which no test server can be reached under.
type rewrite struct {
	target *url.URL
	next   http.RoundTripper
}

func (rw rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("X-Original-Host", req.URL.Host)
	r.URL.Scheme, r.URL.Host = rw.target.Scheme, rw.target.Host
	return rw.next.RoundTrip(r)
}

// server fakes the Entra token endpoint and the blob service on one host.
// The credential decides the answer: the tenant id's first block for a
// client secret, the account name for a storage key, the path for a
// signature.
func server(t *testing.T) (*Provider, func() []call) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls []call
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("User-Agent"), detect.UserAgent) {
			t.Errorf("User-Agent %q does not name patty", r.Header.Get("User-Agent"))
		}
		_ = r.ParseForm()
		c := call{method: r.Method, host: r.Header.Get("X-Original-Host"), path: r.URL.Path, form: map[string]string{}, auth: r.Header.Get("Authorization")}
		for k := range r.Form {
			c.form[k] = r.Form.Get(k)
		}
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			tokenEndpoint(t, w, r)
		case strings.HasSuffix(c.host, ".blob.core.windows.net") && r.URL.Query().Get("sig") != "":
			sasEndpoint(w, r)
		case strings.HasSuffix(c.host, ".blob.core.windows.net"):
			blobEndpoint(t, w, r, c.host)
		default:
			t.Errorf("unexpected request %s %s (host %s)", r.Method, r.URL, c.host)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	p := provider()
	p.LoginURL = srv.URL
	target, _ := url.Parse(srv.URL)
	p.Client = &http.Client{Transport: rewrite{target: target, next: srv.Client().Transport}}
	return p, func() []call {
		mu.Lock()
		defer mu.Unlock()
		return append([]call(nil), calls...)
	}
}

// aadFail answers the way Entra does: the code in error_codes and at the
// start of the description, followed by trace ids.
func aadFail(w http.ResponseWriter, status, code int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(aadError{Error: "invalid_client", Description: fmt.Sprintf("AADSTS%d: %s Trace ID: 0000 Correlation ID: 0000 Timestamp: 2026-09-13 12:00:00Z", code, msg), Codes: []int{code}})
}

func tokenEndpoint(t *testing.T, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		t.Errorf("token requests are posted, got %s", r.Method)
	}
	if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != graphScope || r.Form.Get("client_id") == "" || r.Form.Get("client_secret") == "" {
		t.Errorf("token request form %v", r.Form)
	}
	w.Header().Set("Content-Type", "application/json")
	tenantID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/oauth2/v2.0/token")
	switch first, _, _ := strings.Cut(tenantID, "-"); first {
	case "0badsec0":
		aadFail(w, http.StatusUnauthorized, 7000215, "Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app 'x'.")
	case "0expired":
		aadFail(w, http.StatusUnauthorized, 7000222, "The provided client secret keys for app 'x' are expired.")
	case "0noapp00":
		aadFail(w, http.StatusBadRequest, 700016, "Application with identifier 'x' was not found in the directory 'y'.")
	case "0notena0":
		aadFail(w, http.StatusBadRequest, 90002, "Tenant 'x' not found. Check to make sure you have the correct tenant ID and are signing into the correct cloud.")
	case "0other00":
		aadFail(w, http.StatusBadRequest, 50034, "The user account does not exist in the directory.")
	case "0broken0":
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("<html>gateway</html>"))
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": 3599, "access_token": graphToken(r.Form.Get("client_id"))})
	}
}

// graphToken is an unsigned JWT with the claims a Graph token carries
// about its application.
func graphToken(appID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"aud": "https://graph.microsoft.com", "appid": appID, "app_displayname": "deploy-bot", "tid": tenant})
	return header + "." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
}

func storageFail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("x-ms-error-code", code)
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Error><Code>%s</Code><Message>Server failed to authenticate the request.</Message></Error>`, code)
}

// blobEndpoint answers the container listing by the account in the host;
// every request has to be Shared Key signed for that account.
func blobEndpoint(t *testing.T, w http.ResponseWriter, r *http.Request, host string) {
	account, _, _ := strings.Cut(host, ".")
	if r.Method != http.MethodGet || r.URL.Path != "/" || r.URL.Query().Get("comp") != "list" {
		t.Errorf("storage request %s %s, want GET /?comp=list", r.Method, r.URL)
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "SharedKey "+account+":") {
		t.Errorf("Authorization %q is not Shared Key for %s", auth, account)
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "SharedKey "+account+":")); err != nil {
		t.Errorf("signature is not base64: %v", err)
	}
	if r.Header.Get("x-ms-date") == "" || r.Header.Get("x-ms-version") != apiVersion {
		t.Errorf("x-ms-date %q, x-ms-version %q", r.Header.Get("x-ms-date"), r.Header.Get("x-ms-version"))
	}
	switch account {
	case "rotatedstorage":
		storageFail(w, http.StatusForbidden, "AuthenticationFailed")
	case "walledstorage":
		storageFail(w, http.StatusForbidden, "AuthorizationFailure")
	case "gonestorage":
		storageFail(w, http.StatusNotFound, "ResourceNotFound")
	case "brokenstorage":
		w.WriteHeader(http.StatusInternalServerError)
	case "emptystorage":
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://emptystorage.blob.core.windows.net/"><Containers/><NextMarker/></EnumerationResults>`))
	default:
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Containers><Container><Name>backups</Name></Container><Container><Name>logs</Name></Container><Container><Name>tfstate</Name></Container></Containers><NextMarker/></EnumerationResults>`))
	}
}

// sasEndpoint answers a HEAD by the path: HEAD answers have no body, so the
// code is only in the header.
func sasEndpoint(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.Contains(r.URL.Path, "rotated"):
		w.Header().Set("x-ms-error-code", "AuthenticationFailed")
		w.WriteHeader(http.StatusForbidden)
	case strings.Contains(r.URL.Path, "readonly"):
		w.Header().Set("x-ms-error-code", "AuthorizationPermissionMismatch")
		w.WriteHeader(http.StatusForbidden)
	case strings.Contains(r.URL.Path, "missing"):
		w.Header().Set("x-ms-error-code", "BlobNotFound")
		w.WriteHeader(http.StatusNotFound)
	case strings.Contains(r.URL.Path, "broken"):
		w.WriteHeader(http.StatusInternalServerError)
	default:
		w.Header().Set("Content-Length", "42")
		w.WriteHeader(http.StatusOK)
	}
}

func secretToken(tenantID, clientID string) detect.Token {
	return detect.Token{Kind: KindClientSecret, Value: clientSecret("Ab1"), Secret: principal{Tenant: tenantID, Client: clientID}.encode()}
}

func TestVerifyClientSecret(t *testing.T) {
	p, calls := server(t)
	v := p.Verify(context.Background(), secretToken(tenant, client))
	want := detect.Verification{Status: detect.StatusActive, Detail: "app " + client + " in tenant " + tenant, ClientID: client, App: "deploy-bot"}
	if v != want {
		t.Errorf("live: got %+v, want %+v", v, want)
	}
	for tenantID, want := range map[string]detect.Verification{
		"0badsec0-2222-3333-4444-555555555555": {Status: detect.StatusRevoked, Detail: "invalid client secret for app " + client + " in tenant 0badsec0-2222-3333-4444-555555555555"},
		"0expired-2222-3333-4444-555555555555": {Status: detect.StatusRevoked, Detail: "the client secret has expired (app " + client + " in tenant 0expired-2222-3333-4444-555555555555)"},
		"0noapp00-2222-3333-4444-555555555555": {Status: detect.StatusUnknown, Detail: "app " + client + " not found in tenant 0noapp00-2222-3333-4444-555555555555; wrong tenant id nearby?"},
		"0notena0-2222-3333-4444-555555555555": {Status: detect.StatusUnknown, Detail: "tenant 0notena0-2222-3333-4444-555555555555 not found; wrong tenant id nearby?"},
		"0other00-2222-3333-4444-555555555555": {Status: detect.StatusUnknown, Detail: "AADSTS50034: AADSTS50034: The user account does not exist in the directory."},
		"0broken0-2222-3333-4444-555555555555": {Status: detect.StatusUnknown, Detail: "HTTP 500: "},
	} {
		if v := p.Verify(context.Background(), secretToken(tenantID, client)); v != want {
			t.Errorf("%s: got %+v, want %+v", tenantID, v, want)
		}
	}
	for _, c := range calls() {
		if c.method != http.MethodPost || !strings.HasSuffix(c.path, "/oauth2/v2.0/token") {
			t.Errorf("unexpected request %+v", c)
		}
		if !strings.HasPrefix(strings.TrimPrefix(c.path, "/"), "0") && !strings.HasPrefix(strings.TrimPrefix(c.path, "/"), tenant) {
			t.Errorf("request to a tenant nothing named: %s", c.path)
		}
	}
}

func TestVerifyClientSecretIncomplete(t *testing.T) {
	p, calls := server(t)
	for name, tok := range map[string]detect.Token{
		"nothing":     secretToken("", ""),
		"no tenant":   secretToken("", client),
		"no client":   secretToken(tenant, ""),
		"bare secret": {Kind: KindClientSecret, Value: clientSecret("Ab1")},
	} {
		v := p.Verify(context.Background(), tok)
		if v.Status != detect.StatusUnverifiable || !strings.Contains(v.Detail, "not found near the secret") {
			t.Errorf("%s: %+v", name, v)
		}
	}
	if len(calls()) != 0 {
		t.Errorf("an incomplete secret was sent somewhere: %+v", calls())
	}
}

func TestVerifyStorageKey(t *testing.T) {
	p, calls := server(t)
	key := storageKey('v')
	for acct, want := range map[string]detect.Verification{
		account:          {Status: detect.StatusActive, Detail: "storage account " + account + ", 3 containers"},
		"emptystorage":   {Status: detect.StatusActive, Detail: "storage account emptystorage, 0 containers"},
		"rotatedstorage": {Status: detect.StatusRevoked, Detail: "key rotated: storage account rotatedstorage no longer accepts it"},
		"walledstorage":  {Status: detect.StatusUnknown, Detail: "storage account walledstorage refused the request before judging the key (AuthorizationFailure): a firewall or network rule, or Shared Key access is disabled on the account"},
		"gonestorage":    {Status: detect.StatusRevoked, Detail: "storage account gonestorage does not exist any more (HTTP 404, ResourceNotFound)"},
		"brokenstorage":  {Status: detect.StatusUnknown, Detail: "HTTP 500 from storage account brokenstorage"},
	} {
		tok := detect.Token{Kind: KindStorageAccountKey, Value: key, Secret: acct}
		if v := p.Verify(context.Background(), tok); v != want {
			t.Errorf("%s: got %+v, want %+v", acct, v, want)
		}
	}
	if v := p.Verify(context.Background(), detect.Token{Kind: KindStorageAccountKey, Value: key}); v.Status != detect.StatusUnverifiable {
		t.Errorf("key without account: %+v", v)
	}
	if v := p.Verify(context.Background(), detect.Token{Kind: KindStorageAccountKey, Value: "not base64!", Secret: account}); v.Status != detect.StatusUnverifiable || !strings.HasPrefix(v.Detail, "malformed key") {
		t.Errorf("malformed key: %+v", v)
	}
	got := calls()
	if len(got) != 6 {
		t.Fatalf("%d requests, want one per account: %+v", len(got), got)
	}
	for _, c := range got {
		if c.method != http.MethodGet || c.path != "/" || !strings.HasSuffix(c.host, ".blob.core.windows.net") {
			t.Errorf("unexpected request %+v", c)
		}
		if strings.Contains(c.auth, key) {
			t.Error("the key itself was sent")
		}
	}
}

func TestVerifyStorageKeyUnresolvable(t *testing.T) {
	p := provider()
	p.BlobEndpoint = "https://{account}.invalid"
	v := p.Verify(context.Background(), detect.Token{Kind: KindStorageAccountKey, Value: storageKey('v'), Secret: "nonexistentacct"})
	if v.Status != detect.StatusUnknown || !strings.Contains(v.Detail, "does not resolve") {
		t.Errorf("unresolvable account: %+v", v)
	}
}

func sasToken(host, path, expires string) detect.Token {
	raw := sasURL(host, path, expires, "s1g%3D")
	return detect.Token{Kind: KindSASToken, Value: "s1g=", Secret: raw}
}

func TestVerifySAS(t *testing.T) {
	p, calls := server(t)
	host := account + ".blob.core.windows.net"
	for path, want := range map[string]detect.Verification{
		"/backups/db.bak": {Status: detect.StatusActive, Detail: "accepted by " + host + "/backups/db.bak", Expires: "2030-01-01"},
		"/readonly/x":     {Status: detect.StatusActive, Detail: "accepted by " + host + "/readonly/x, but not permitted to read it (AuthorizationPermissionMismatch)", Expires: "2030-01-01"},
		"/rotated/x":      {Status: detect.StatusRevoked, Detail: host + "/rotated/x rejects the signature: the key that signed it was rotated, or its access policy is gone"},
		"/missing/x":      {Status: detect.StatusUnknown, Detail: "the signature was not rejected, but " + host + "/missing/x does not exist (HTTP 404, BlobNotFound)"},
		"/broken/x":       {Status: detect.StatusUnknown, Detail: "HTTP 500 from " + host + "/broken/x"},
	} {
		if v := p.Verify(context.Background(), sasToken(host, path, "2030-01-01T00%3A00%3A00Z")); v != want {
			t.Errorf("%s: got %+v, want %+v", path, v, want)
		}
	}
	for _, c := range calls() {
		if c.method != http.MethodHead || c.host != host {
			t.Errorf("unexpected request %+v", c)
		}
	}
	before := len(calls())
	// Expired: no request. Bare: nothing to ask. Not a storage host, or
	// not https: not contacted.
	if v := p.Verify(context.Background(), sasToken(host, "/backups/db.bak", "2024-06-30")); v.Status != detect.StatusRevoked || v.Detail != "expired on 2024-06-30; no storage service accepts an expired signature" {
		t.Errorf("expired: %+v", v)
	}
	bare := detect.Token{Kind: KindSASToken, Value: "s1g=", Secret: "sv=2022-11-02&se=2030-01-01&sig=s1g%3D"}
	if v := p.Verify(context.Background(), bare); v.Status != detect.StatusUnverifiable || !strings.Contains(v.Detail, "bare token") {
		t.Errorf("bare: %+v", v)
	}
	if v := p.Verify(context.Background(), sasToken("evil.example.com", "/x", "2030-01-01")); v.Status != detect.StatusUnverifiable || !strings.Contains(v.Detail, "not an https Azure Storage endpoint") {
		t.Errorf("foreign host: %+v", v)
	}
	plain := sasToken(host, "/x", "2030-01-01")
	plain.Secret = "http" + strings.TrimPrefix(plain.Secret, "https")
	if v := p.Verify(context.Background(), plain); v.Status != detect.StatusUnverifiable {
		t.Errorf("http URL: %+v", v)
	}
	if v := p.Verify(context.Background(), detect.Token{Kind: KindSASToken, Value: "x", Secret: "not a signature"}); v.Status != detect.StatusUnknown {
		t.Errorf("unparseable: %+v", v)
	}
	if len(calls()) != before {
		t.Errorf("something was sent for a signature that must not be checked: %+v", calls()[before:])
	}
	if v := p.Verify(context.Background(), detect.Token{Kind: "azure-something-else"}); v.Status != detect.StatusUnknown {
		t.Errorf("unknown kind: %+v", v)
	}
}

func TestStorageHost(t *testing.T) {
	for host, want := range map[string]bool{
		account + ".blob.core.windows.net":       true,
		account + ".dfs.core.windows.net":        true,
		account + ".blob.core.chinacloudapi.cn":  true,
		account + ".blob.core.usgovcloudapi.net": true,
		"core.windows.net":                       false,
		"example.com":                            false,
		"blob.core.windows.net.example.com":      false,
	} {
		if got := storageHost(host); got != want {
			t.Errorf("storageHost(%q) = %v", host, got)
		}
	}
}
