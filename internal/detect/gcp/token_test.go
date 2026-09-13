package gcp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// Every fixture is assembled at runtime so no key-shaped literal is
// committed: the RSA key is generated, the token bodies are repeated
// patterns of the right alphabet and length.
const (
	email    = "deploy@example-project.iam.gserviceaccount.com"
	project  = "example-project"
	keyID    = "0123456789abcdef0123456789abcdef01234567"
	clientID = "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"
)

var find = New().Find

// rsaKey generates a small RSA key once; the size is irrelevant to the
// shape and keeps the tests fast.
var rsaKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return key
}()

// keyPEM is the PKCS #8 PEM Google writes into a key file.
func keyPEM(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// serviceAccountJSON builds a key file the way `gcloud iam service-accounts
// keys create` does; extra overrides or removes fields.
func serviceAccountJSON(t *testing.T, extra map[string]string) string {
	t.Helper()
	fields := map[string]string{
		"type":                        "service_account",
		"project_id":                  project,
		"private_key_id":              keyID,
		"private_key":                 keyPEM(t),
		"client_email":                email,
		"client_id":                   "123456789012345678901",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/deploy%40example-project.iam.gserviceaccount.com",
		"universe_domain":             "googleapis.com",
	}
	for k, v := range extra {
		if v == "" {
			delete(fields, k)
		} else {
			fields[k] = v
		}
	}
	raw, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func refreshToken(fill string) string { return refreshPrefix + strings.Repeat(fill, 25) }
func accessToken(fill string) string  { return accessPrefix + strings.Repeat(fill, 50) }
func apiKey(fill string) string       { return apiKeyPrefix + strings.Repeat(fill, 35) }

// authorizedUserJSON is what `gcloud auth application-default login` writes.
func authorizedUserJSON(refresh string) string {
	raw, _ := json.Marshal(map[string]string{
		"type":          "authorized_user",
		"client_id":     clientID,
		"client_secret": "d-" + strings.Repeat("s3cr", 8),
		"refresh_token": refresh,
	})
	return string(raw)
}

func TestFindServiceAccountKey(t *testing.T) {
	doc := serviceAccountJSON(t, nil)
	want := email + "/" + keyID
	for name, content := range map[string]string{
		"plain":     doc,
		"yaml":      "apiVersion: v1\nkind: ConfigMap\ndata:\n  key.json: |\n" + indent(doc, "    ") + "\n",
		"terraform": "resource \"google_service_account\" \"deploy\" {}\nlocals {\n  creds = <<EOT\n" + doc + "\nEOT\n}\n",
		"env":       "GOOGLE_CREDENTIALS='" + strings.ReplaceAll(doc, "\n", "") + "'\n",
		"escaped":   `{"auths":{"gcr.io":{"username":"_json_key","password":` + strconv.Quote(doc) + `}}}`,
	} {
		found := find([]byte(content))
		if len(found) != 1 {
			t.Fatalf("%s: found %d tokens, want 1: %+v", name, len(found), found)
		}
		tok := found[0]
		if tok.Kind != KindServiceAccountKey || tok.Value != want {
			t.Errorf("%s: got %s %q, want %s %q", name, tok.Kind, tok.Value, KindServiceAccountKey, want)
		}
		if tok.Attribution != "service account "+email+", project "+project {
			t.Errorf("%s: attribution %q", name, tok.Attribution)
		}
		cred := decodeCredential(tok)
		if !strings.Contains(cred.PrivateKey, "PRIVATE KEY") || cred.Project != project || cred.TokenURI != "https://oauth2.googleapis.com/token" {
			t.Errorf("%s: secret does not carry the key, project and token_uri: %+v", name, cred)
		}
		if content[tok.Offset] != '{' {
			t.Errorf("%s: offset %d is not at the document's brace", name, tok.Offset)
		}
	}
}

func indent(s, prefix string) string {
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}

func TestFindServiceAccountKeyIncomplete(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"no private key": {"private_key": ""},
		"no email":       {"client_email": ""},
		"other type":     {"type": "external_account"},
	} {
		if found := find([]byte(serviceAccountJSON(t, extra))); len(found) != 0 {
			t.Errorf("%s: found %+v", name, found)
		}
	}
	// Without a key id the account alone names the key; without a project
	// the attribution says only whose it is.
	found := find([]byte(serviceAccountJSON(t, map[string]string{"private_key_id": "", "project_id": ""})))
	if len(found) != 1 || found[0].Value != email || found[0].Attribution != "service account "+email {
		t.Errorf("minimal document: %+v", found)
	}
	// A malformed key is still a finding, Verify says it is malformed.
	found = find([]byte(serviceAccountJSON(t, map[string]string{"private_key": "not a key"})))
	if len(found) != 1 || decodeCredential(found[0]).PrivateKey != "not a key" {
		t.Errorf("malformed key: %+v", found)
	}
	// A Terraform resource type, a YAML mapping and an unterminated
	// document are not credential documents.
	for _, content := range []string{
		`resource "google_service_account" "x" { account_id = "service_account" }`,
		"type: service_account\nclient_email: " + email + "\n",
		`{"type": "service_account", "client_email": "` + email + `", "private_key": "x"`,
		`type = "service_account"`,
	} {
		if found := find([]byte(content)); len(found) != 0 {
			t.Errorf("%q: found %+v", content, found)
		}
	}
}

func TestFindAuthorizedUser(t *testing.T) {
	refresh := refreshToken("Rf-t")
	content := "credentials: '" + authorizedUserJSON(refresh) + "'\n"
	found := find([]byte(content))
	if len(found) != 1 {
		t.Fatalf("found %d tokens, want the authorized_user document only: %+v", len(found), found)
	}
	tok := found[0]
	if tok.Kind != KindUserCredentials || tok.Value != refresh {
		t.Errorf("got %s %q", tok.Kind, tok.Value)
	}
	if tok.Attribution != "ADC for OAuth client 123456789012" {
		t.Errorf("attribution %q", tok.Attribution)
	}
	if cred := decodeCredential(tok); cred.ClientID != clientID || !strings.HasPrefix(cred.ClientSecret, "d-") {
		t.Errorf("secret does not carry the client: %+v", cred)
	}
	// The same refresh token elsewhere in the object is still one finding
	// per shape: the bare one is suppressed only where the document
	// carries it.
	other := refreshToken("Oth3")
	found = find([]byte(authorizedUserJSON(refresh) + "\nREFRESH=" + other + "\n"))
	if len(found) != 2 || found[1].Kind != KindRefreshToken || found[1].Value != other {
		t.Errorf("bare token next to a document: %+v", found)
	}
	if found := find([]byte(`{"type": "authorized_user", "client_id": "` + clientID + `"}`)); len(found) != 0 {
		t.Errorf("a document without a refresh token: %+v", found)
	}
}

func TestFindBareTokens(t *testing.T) {
	access, refresh, key := accessToken("Ac-3"), refreshToken("Rf_t"), apiKey("k")
	content := "export CLOUDSDK_AUTH_ACCESS_TOKEN=" + access + "\nrefresh: " + refresh + "\nurl: https://maps.googleapis.com/maps/api/js?key=" + key + "&v=3\n"
	found := find([]byte(content))
	want := []struct {
		kind  detect.Kind
		value string
	}{{KindAccessToken, access}, {KindRefreshToken, refresh}, {KindAPIKey, key}}
	if len(found) != len(want) {
		t.Fatalf("found %d tokens, want %d: %+v", len(found), len(want), found)
	}
	for i, w := range want {
		if found[i].Kind != w.kind || found[i].Value != w.value || found[i].ChecksumVerified {
			t.Errorf("token %d: %+v, want %s %q", i, found[i], w.kind, w.value)
		}
		if strings.Index(content, w.value) != found[i].Offset {
			t.Errorf("token %d: offset %d", i, found[i].Offset)
		}
	}
	if found[1].Attribution != "found without its OAuth client" {
		t.Errorf("bare refresh token attribution %q", found[1].Attribution)
	}
}

func TestFindAccessTokenDots(t *testing.T) {
	// The `ya29.c.` family has a dot inside the body; a dot after the
	// token is punctuation.
	dotted := accessPrefix + "c." + strings.Repeat("Ab0_", 50)
	found := find([]byte("token " + dotted + ".\n"))
	if len(found) != 1 || found[0].Value != dotted {
		t.Errorf("dotted body: %+v", found)
	}
}

func TestFindNearMisses(t *testing.T) {
	for name, content := range map[string]string{
		"access too short":      accessPrefix + strings.Repeat("a", accessMin-1),
		"access too long":       accessPrefix + strings.Repeat("a", accessMax+1),
		"access in a word":      "xya29." + strings.Repeat("a", 100),
		"access bad alphabet":   accessPrefix + strings.Repeat("a", 50) + "+" + strings.Repeat("a", 50),
		"refresh too short":     refreshPrefix + strings.Repeat("a", refreshMin-1),
		"refresh too long":      refreshPrefix + strings.Repeat("a", refreshMax+1),
		"refresh in a number":   "21//0" + strings.Repeat("a", 60),
		"api key short":         apiKeyPrefix + strings.Repeat("a", apiKeyLen-1),
		"api key long":          apiKeyPrefix + strings.Repeat("a", apiKeyLen+1),
		"api key in a word":     "xAIza" + strings.Repeat("a", apiKeyLen),
		"api key bad alphabet":  apiKeyPrefix + strings.Repeat("a", 20) + "/" + strings.Repeat("a", 14),
		"prefix only":           "ya29. 1//0 AIza",
		"the words in the docs": "gcloud auth print-access-token prints a ya29. token; refresh tokens start with 1//0",
	} {
		if found := find([]byte(content)); len(found) != 0 {
			t.Errorf("%s: found %+v", name, found)
		}
	}
}

func TestSecretIsNotPrinted(t *testing.T) {
	doc := serviceAccountJSON(t, nil)
	for _, tok := range find([]byte(doc)) {
		if strings.Contains(tok.Value, "PRIVATE") || strings.Contains(tok.Attribution, "PRIVATE") {
			t.Errorf("the private key leaked into the printable fields: %+v", tok)
		}
		if detect.Redact(tok.Value) == "" {
			t.Error("value redacts to nothing")
		}
	}
	// The escaped form round-trips the key.
	found := find([]byte(strconv.Quote(doc)))
	if len(found) != 1 {
		t.Fatalf("escaped document: %+v", found)
	}
	if _, err := parsePrivateKey(decodeCredential(found[0]).PrivateKey); err != nil {
		t.Errorf("the key inside an escaped document does not parse: %v", err)
	}
}

func TestCredentialEncoding(t *testing.T) {
	if (credential{}).encode() != "" {
		t.Error("an empty credential must encode to nothing so bare tokens carry no secret")
	}
	tok := detect.Token{Secret: credential{ClientID: clientID}.encode()}
	if decodeCredential(tok).ClientID != clientID {
		t.Error("round trip lost the client id")
	}
	if got := clientPrefix(""); got != "(unknown)" {
		t.Errorf("clientPrefix(\"\") = %q", got)
	}
}
