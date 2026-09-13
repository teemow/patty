package npm

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindAccessToken is an access token of the current format (npm_).
	KindAccessToken detect.Kind = "npm-access-token"
	// KindLegacyToken is a UUID token from before 2021, only recognised as
	// the _authToken of an .npmrc line.
	KindLegacyToken detect.Kind = "npm-legacy-token"
)

const (
	prefix    = "npm_"
	bodyLen   = 36
	uuidLen   = 36
	authToken = "_authToken"
)

// companion is what Token.Secret carries: the registry an .npmrc line
// bound the token to, when it was found on one. JSON so that a bare token
// merges with the same token found on an .npmrc line.
type companion struct {
	Registry string `json:"registry,omitempty"`
}

func (c companion) encode() string {
	if c == (companion{}) {
		return ""
	}
	raw, _ := json.Marshal(c)
	return string(raw)
}

func decode(tok detect.Token) companion {
	var c companion
	_ = json.Unmarshal([]byte(tok.Secret), &c)
	return c
}

// Find implements detect.Provider. One substring pass finds the npm_
// prefix; each candidate is checked for 36 alphanumerics standing on their
// own. One more pass finds `_authToken`, whose value is a token whatever
// its shape: a UUID there is a legacy token, and an npm_ token there
// learns which registry the line is for.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	found = detect.ScanPrefix(found, content, prefix, func(start int) (detect.Token, bool) { return accessTokenAt(content, start) })
	return detect.ScanPrefix(found, content, authToken, func(start int) (detect.Token, bool) {
		return authTokenAt(content, start, &found)
	})
}

func accessTokenAt(content []byte, start int) (detect.Token, bool) {
	end := start + len(prefix) + bodyLen
	if detect.WordBefore(content, start) || end > len(content) || !detect.All(content[start+len(prefix):end], detect.IsAlnum) || detect.AlnumAt(content, end) || (end < len(content) && content[end] == '_') {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindAccessToken, Value: string(content[start:end]), Offset: start}, true
}

// authTokenAt reads the value of an .npmrc `_authToken` setting:
// `//registry.example.com/:_authToken=<token>`, or a bare
// `_authToken=<token>` for the default registry. A UUID value is a legacy
// token. An npm_ token, which the first pass already found, is not a
// second finding; it gets the line's registry instead. Anything else
// (a GitHub token for npm.pkg.github.com) belongs to another provider.
func authTokenAt(content []byte, start int, found *[]detect.Token) (detect.Token, bool) {
	pos := start + len(authToken)
	pos += detect.Span(content, pos, 4, isSpace)
	if pos >= len(content) || content[pos] != '=' {
		return detect.Token{}, false
	}
	pos += 1 + detect.Span(content, pos+1, 4, isSpace)
	pos += detect.Span(content, pos, 1, isQuote)
	registry := registryOf(content, start)
	if n := detect.Span(content, pos, len(prefix)+bodyLen+1, isTokenByte); n == len(prefix)+bodyLen && string(content[pos:pos+len(prefix)]) == prefix {
		for i := range *found {
			if (*found)[i].Offset == pos {
				(*found)[i].Secret = companion{Registry: registry}.encode()
				(*found)[i].Attribution = attribution(registry)
			}
		}
		return detect.Token{}, false
	}
	end := pos + uuidLen
	if end > len(content) || !isUUID(content[pos:end]) || detect.AlnumAt(content, end) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindLegacyToken, Value: string(content[pos:end]), Offset: pos, Secret: companion{Registry: registry}.encode(), Attribution: attribution(registry)}, true
}

// registryOf reads the `//host/path:` that precedes _authToken on its
// line and returns the registry's URL, https assumed; "" when the setting
// is the bare `_authToken` of the default registry.
func registryOf(content []byte, start int) string {
	lineStart := bytes.LastIndexByte(content[:start], '\n') + 1
	line := string(content[lineStart:start])
	i := strings.LastIndex(line, "//")
	if i < 0 || !strings.HasSuffix(line, ":") {
		return ""
	}
	host := strings.TrimSuffix(line[i+2:], ":")
	host = strings.TrimSuffix(host, "/")
	if host == "" || strings.ContainsAny(host, " \t\"'") {
		return ""
	}
	return "https://" + host
}

func attribution(registry string) string {
	if registry == "" {
		return "in an .npmrc for the default registry"
	}
	return "in an .npmrc for " + detect.HostOf(registry)
}

// isUUID reports whether b is a lower-case UUID: 8-4-4-4-12 hex digits.
func isUUID(b []byte) bool {
	if len(b) != uuidLen {
		return false
	}
	for i, c := range b {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isLowerHex(c) {
				return false
			}
		}
	}
	return true
}

func isLowerHex(c byte) bool  { return detect.IsDigit(c) || (c >= 'a' && c <= 'f') }
func isTokenByte(c byte) bool { return detect.IsAlnum(c) || c == '_' }
func isSpace(c byte) bool     { return c == ' ' || c == '\t' }
func isQuote(c byte) bool     { return c == '"' || c == '\'' }
