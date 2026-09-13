package gcp

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindServiceAccountKey is the JSON key of a service account; its name
	// is `client_email/private_key_id`, the private key travels apart.
	KindServiceAccountKey detect.Kind = "gcp-service-account-key"
	// KindUserCredentials is the `authorized_user` JSON gcloud writes as
	// application default credentials: a refresh token with the OAuth
	// client it was issued to. Its name is the refresh token.
	KindUserCredentials detect.Kind = "gcp-oauth-user-credentials"
	// KindAccessToken is a bare OAuth 2.0 access token (ya29.).
	KindAccessToken detect.Kind = "gcp-oauth-access-token"
	// KindRefreshToken is a bare OAuth 2.0 refresh token (1//0) found
	// without the client it belongs to.
	KindRefreshToken detect.Kind = "gcp-oauth-refresh-token"
	// KindAPIKey is an API key (AIza).
	KindAPIKey detect.Kind = "gcp-api-key"
)

const (
	accessPrefix  = "ya29."
	refreshPrefix = "1//0"
	apiKeyPrefix  = "AIza"
	// accessMin and accessMax bound the body of an access token, and
	// refreshMin and refreshMax that of a refresh token. Neither format is
	// documented; tokens seen in the wild have around 200 and 100
	// characters, so the bounds leave room without accepting arbitrary
	// base64 runs.
	accessMin, accessMax   = 60, 250
	refreshMin, refreshMax = 40, 120
	// apiKeyLen is the body of an API key, which is fixed.
	apiKeyLen = 35
	// maxObject bounds the JSON document a type marker is looked up in; a
	// service account key is a little over two kilobytes.
	maxObject = 32 << 10
)

// typeMarkers are the `type` values of the two credential documents.
var typeMarkers = []string{"service_account", "authorized_user"}

// credential is what Token.Secret carries for this provider: the material
// Value does not hold. It is JSON so a bare refresh token, which has none
// of it, merges with the same token found in an authorized_user document,
// which knows its client.
type credential struct {
	PrivateKey   string `json:"private_key,omitempty"`
	TokenURI     string `json:"token_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Project      string `json:"project,omitempty"`
}

func (c credential) encode() string {
	if c == (credential{}) {
		return ""
	}
	raw, _ := json.Marshal(c)
	return string(raw)
}

func decodeCredential(tok detect.Token) credential {
	var c credential
	_ = json.Unmarshal([]byte(tok.Secret), &c)
	return c
}

// Find implements detect.Provider: the credential documents first, found by
// their `type` field and parsed as JSON wherever they are embedded, then
// the bare token shapes. A refresh token that is the one an authorized_user
// document carries is that document's finding, not a bare token too.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	inDocument := map[string]bool{}
	for _, marker := range typeMarkers {
		found = detect.ScanPrefix(found, content, marker, func(start int) (detect.Token, bool) {
			tok, ok := documentAt(content, start, marker)
			if ok && tok.Kind == KindUserCredentials {
				inDocument[tok.Value] = true
			}
			return tok, ok
		})
	}
	found = detect.ScanPrefix(found, content, accessPrefix, func(start int) (detect.Token, bool) { return accessTokenAt(content, start) })
	found = detect.ScanPrefix(found, content, refreshPrefix, func(start int) (detect.Token, bool) {
		tok, ok := refreshTokenAt(content, start)
		return tok, ok && !inDocument[tok.Value]
	})
	return detect.ScanPrefix(found, content, apiKeyPrefix, func(start int) (detect.Token, bool) { return apiKeyAt(content, start) })
}

// documentAt reads the JSON object around a `type` marker. The marker has
// to be a JSON string value: quoted, or quote-escaped when the whole
// document sits inside another JSON string (the password of a Docker
// config). Anything else, a Terraform resource type or a YAML mapping, is
// not a credential document.
func documentAt(content []byte, start int, marker string) (detect.Token, bool) {
	end := start + len(marker)
	if start == 0 || content[start-1] != '"' || end >= len(content) || (content[end] != '"' && content[end] != '\\') {
		return detect.Token{}, false
	}
	open, closing, ok := enclosingObject(content, start)
	if !ok {
		return detect.Token{}, false
	}
	fields, ok := parseObject(content[open:closing])
	if !ok || fields["type"] != marker {
		return detect.Token{}, false
	}
	switch marker {
	case "service_account":
		return serviceAccountKey(fields, open)
	default:
		return userCredentials(fields, open)
	}
}

// enclosingObject finds the braces around position pos: back to the `{`
// that has no match before pos, forward to its `}`. Braces are counted
// without regard to strings, which the fields of a credential document
// never contain; a document larger than maxObject is not one.
func enclosingObject(content []byte, pos int) (open, closing int, ok bool) {
	depth := 0
	for open = pos - 1; open >= 0 && pos-open <= maxObject; open-- {
		switch content[open] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				closing, ok = forwardMatch(content, open)
				return open, closing, ok
			}
			depth--
		}
	}
	return 0, 0, false
}

func forwardMatch(content []byte, open int) (int, bool) {
	depth := 0
	for i := open; i < len(content) && i-open <= maxObject; i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// parseObject decodes a JSON object to its string fields. Text that is not
// JSON is tried once more as the content of a JSON string, which is how a
// credential document looks when it is the value of another one.
func parseObject(raw []byte) (map[string]string, bool) {
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		unescaped, err := strconv.Unquote(`"` + string(raw) + `"`)
		if err != nil || json.Unmarshal([]byte(unescaped), &obj) != nil {
			return nil, false
		}
	}
	fields := make(map[string]string, len(obj))
	for k, v := range obj {
		if s, ok := v.(string); ok {
			fields[k] = s
		}
	}
	return fields, true
}

// serviceAccountKey is the finding for a service account key: named by
// the account and the key id, with the private key kept apart. A
// document without its private key or account is a stub, not a key.
func serviceAccountKey(fields map[string]string, offset int) (detect.Token, bool) {
	email, key := fields["client_email"], fields["private_key"]
	if email == "" || key == "" {
		return detect.Token{}, false
	}
	value := email
	if id := fields["private_key_id"]; id != "" {
		value += "/" + id
	}
	attribution := "service account " + email
	if project := fields["project_id"]; project != "" {
		attribution += ", project " + project
	}
	return detect.Token{
		Kind:        KindServiceAccountKey,
		Value:       value,
		Offset:      offset,
		Attribution: attribution,
		Secret:      credential{PrivateKey: key, TokenURI: fields["token_uri"], Project: fields["project_id"]}.encode(),
	}, true
}

// userCredentials is the finding for an authorized_user document: the
// refresh token, with the OAuth client that can exchange it kept apart.
func userCredentials(fields map[string]string, offset int) (detect.Token, bool) {
	refresh := fields["refresh_token"]
	if refresh == "" {
		return detect.Token{}, false
	}
	return detect.Token{
		Kind:        KindUserCredentials,
		Value:       refresh,
		Offset:      offset,
		Attribution: "ADC for OAuth client " + clientPrefix(fields["client_id"]),
		Secret:      credential{ClientID: fields["client_id"], ClientSecret: fields["client_secret"]}.encode(),
	}, true
}

// clientPrefix is the project number an OAuth client id starts with,
// `123456789012-abc.apps.googleusercontent.com` → `123456789012`; enough to
// tell clients apart without repeating the whole id.
func clientPrefix(id string) string {
	if id == "" {
		return "(unknown)"
	}
	prefix, _, _ := strings.Cut(id, "-")
	return prefix
}

// accessTokenAt matches `ya29.` and a body of the URL-safe base64 alphabet
// with dots, which the `ya29.c.` family has, of a plausible length.
func accessTokenAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	body := start + len(accessPrefix)
	n := detect.Span(content, body, accessMax+1, func(c byte) bool { return detect.IsBase64URL(c) || c == '.' })
	for n > 0 && content[body+n-1] == '.' {
		n--
	}
	if n < accessMin || n > accessMax || detect.Base64URLAt(content, body+n) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindAccessToken, Value: string(content[start : body+n]), Offset: start}, true
}

// refreshTokenAt matches `1//0` and a body of the URL-safe base64 alphabet
// of a plausible length.
func refreshTokenAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	body := start + len(refreshPrefix)
	n := detect.Span(content, body, refreshMax+1, detect.IsBase64URL)
	if n < refreshMin || n > refreshMax {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindRefreshToken, Value: string(content[start : body+n]), Offset: start, Attribution: "found without its OAuth client"}, true
}

// apiKeyAt matches `AIza` and exactly 35 characters of the URL-safe base64
// alphabet, not part of a longer word.
func apiKeyAt(content []byte, start int) (detect.Token, bool) {
	end := start + len(apiKeyPrefix) + apiKeyLen
	if detect.WordBefore(content, start) || end > len(content) || detect.Base64URLAt(content, end) {
		return detect.Token{}, false
	}
	if !detect.All(content[start+len(apiKeyPrefix):end], detect.IsBase64URL) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindAPIKey, Value: string(content[start:end]), Offset: start}, true
}
