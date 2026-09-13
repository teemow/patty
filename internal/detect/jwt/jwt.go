// Package jwt reads JSON Web Tokens without verifying them. patty has no
// key to check a signature with and never claims to: what it takes from a
// token is who issued it, to whom, and until when, so a provider can tell
// its own tokens from everyone else's and say what a leaked one is. Bare
// tokens of no known issuer are not findings; a provider decides what to
// report.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Prefix is how the base64url of a JSON object starts, and so every JWT.
const Prefix = "eyJ"

// maxLen bounds a token candidate; a bound service account token is well
// under two kilobytes, an OIDC token with many claims a few.
const maxLen = 8192

// Claims is the decoded payload of a token, with the registered claims
// picked out and everything kept in Raw.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	// Expires and IssuedAt are zero when the token has no exp or iat.
	Expires  time.Time
	IssuedAt time.Time
	Raw      map[string]any
	Header   map[string]any
}

// Expired reports whether the token names an expiry that has passed.
func (c Claims) Expired(now time.Time) bool {
	return !c.Expires.IsZero() && c.Expires.Before(now)
}

// String reads a string claim from the payload, "" when absent or not a string.
func (c Claims) String(name string) string {
	s, _ := c.Raw[name].(string)
	return s
}

// Object reads a nested object claim from the payload, nil when absent.
func (c Claims) Object(name string) map[string]any {
	m, _ := c.Raw[name].(map[string]any)
	return m
}

// Decode splits a token into header, payload and signature and decodes the
// first two. The signature is kept out: it is not checked. A string that is
// not three base64url parts with JSON objects in the first two is not a
// token.
func Decode(token string) (Claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return Claims{}, false
	}
	var c Claims
	if !decodePart(parts[0], &c.Header) || !decodePart(parts[1], &c.Raw) {
		return Claims{}, false
	}
	c.Issuer = c.String("iss")
	c.Subject = c.String("sub")
	switch aud := c.Raw["aud"].(type) {
	case string:
		c.Audience = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	}
	c.Expires = unix(c.Raw["exp"])
	c.IssuedAt = unix(c.Raw["iat"])
	return c, true
}

func decodePart(part string, into *map[string]any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(part, "="))
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, into) == nil && *into != nil
}

// unix reads a NumericDate claim; JSON numbers arrive as float64.
func unix(v any) time.Time {
	f, ok := v.(float64)
	if !ok || f <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(f), 0).UTC()
}

// Candidate is a token found in content.
type Candidate struct {
	Value  string
	Offset int
	Claims Claims
}

// Find returns every well-formed token in content, word-bounded: a token
// glued to a longer run of base64 is part of that run, not a token.
func Find(content []byte) []Candidate {
	var out []Candidate
	detect.ScanPrefix(nil, content, Prefix, func(start int) (detect.Token, bool) {
		if start > 0 && (detect.IsBase64URL(content[start-1]) || content[start-1] == '.') {
			return detect.Token{}, false
		}
		n := detect.Span(content, start, maxLen, isTokenChar)
		if detect.Base64URLAt(content, start+n) {
			return detect.Token{}, false
		}
		value := strings.TrimRight(string(content[start:start+n]), ".")
		if c, ok := Decode(value); ok {
			out = append(out, Candidate{Value: value, Offset: start, Claims: c})
		}
		return detect.Token{}, false
	})
	return out
}

func isTokenChar(c byte) bool { return detect.IsBase64URL(c) || c == '.' || c == '=' }
