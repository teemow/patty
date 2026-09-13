package anthropic

import (
	"bytes"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindAPIKey is an API key (sk-ant-api03-).
	KindAPIKey detect.Kind = "anthropic-api-key"
	// KindAdminKey is an Admin API key (sk-ant-admin01-), which manages the
	// organization rather than calling models.
	KindAdminKey detect.Kind = "anthropic-admin-api-key"
	// KindOAuth is the OAuth access token of a Claude Code sign-in (sk-ant-oat01-).
	KindOAuth detect.Kind = "anthropic-oauth-token"
	// KindRefresh is the OAuth refresh token that goes with it (sk-ant-ort01-).
	KindRefresh detect.Kind = "anthropic-oauth-refresh-token"
)

const (
	// stem is what every family starts with; one substring pass finds them all.
	stem = "sk-ant-"
	// keyBodyLen is the random part of an API or admin key, followed by keySuffix.
	keyBodyLen = 93
	keySuffix  = "AA"
	// oauthMin and oauthMax bound the body of an OAuth token. Anthropic does
	// not document the format; tokens seen in the wild have 95 characters,
	// so the range leaves room without accepting arbitrary base64 runs.
	oauthMin = 80
	oauthMax = 120
)

// families lists the prefixes after the stem. Fixed families have exactly
// keyBodyLen characters plus keySuffix; the others a body within the OAuth
// bounds.
var families = []struct {
	prefix string
	kind   detect.Kind
	fixed  bool
}{
	{"api03-", KindAPIKey, true},
	{"admin01-", KindAdminKey, true},
	{"oat01-", KindOAuth, false},
	{"ort01-", KindRefresh, false},
}

// Find implements detect.Provider. One substring pass for the shared stem,
// then the exact shape of the family at each candidate: alphabet, length,
// the AA suffix of a key, and no continuation into a longer word.
func (*Provider) Find(content []byte) []detect.Token {
	return detect.ScanPrefix(nil, content, stem, func(start int) (detect.Token, bool) { return keyAt(content, start) })
}

func keyAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	rest := content[start+len(stem):]
	for _, f := range families {
		if !bytes.HasPrefix(rest, []byte(f.prefix)) {
			continue
		}
		body := start + len(stem) + len(f.prefix)
		var end int
		if f.fixed {
			end = body + keyBodyLen + len(keySuffix)
			if end > len(content) || !detect.All(content[body:end-len(keySuffix)], detect.IsBase64URL) || string(content[end-len(keySuffix):end]) != keySuffix {
				return detect.Token{}, false
			}
		} else {
			n := detect.Span(content, body, oauthMax+1, detect.IsBase64URL)
			if n < oauthMin || n > oauthMax {
				return detect.Token{}, false
			}
			end = body + n
		}
		if detect.Base64URLAt(content, end) {
			return detect.Token{}, false
		}
		return detect.Token{Kind: f.kind, Value: string(content[start:end]), Offset: start}, true
	}
	return detect.Token{}, false
}
