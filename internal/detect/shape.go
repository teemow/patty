package detect

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// UserAgent identifies patty to the provider APIs.
const UserAgent = "patty"

// ScanPrefix finds every occurrence of prefix in content and calls at with
// its offset; at returns the token when the bytes there have the exact
// shape. Matches are appended to found.
func ScanPrefix(found []Token, content []byte, prefix string, at func(start int) (Token, bool)) []Token {
	needle := []byte(prefix)
	idx := 0
	for {
		i := bytes.Index(content[idx:], needle)
		if i < 0 {
			return found
		}
		start := idx + i
		if tok, ok := at(start); ok {
			found = append(found, tok)
		}
		idx = start + len(needle)
	}
}

// IsAlnum reports whether c is an ASCII letter or digit.
func IsAlnum(c byte) bool {
	return IsDigit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// IsDigit reports whether c is an ASCII digit.
func IsDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// IsHex reports whether c is a lower- or upper-case hexadecimal digit.
func IsHex(c byte) bool {
	return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// IsBase64URL reports whether c is in the URL-safe base64 alphabet, which
// most API keys are made of.
func IsBase64URL(c byte) bool {
	return IsAlnum(c) || c == '-' || c == '_'
}

// All reports whether every byte of b satisfies ok. The empty slice does.
func All(b []byte, ok func(byte) bool) bool {
	for _, c := range b {
		if !ok(c) {
			return false
		}
	}
	return true
}

// AlnumAt reports whether content has an alphanumeric byte at i; false past
// the end. Used to reject candidates that continue into a longer word.
func AlnumAt(content []byte, i int) bool {
	return i < len(content) && IsAlnum(content[i])
}

// WordBefore reports whether the byte before position i continues a word
// into the candidate: a letter, digit or underscore. False at the start.
func WordBefore(content []byte, i int) bool {
	return i > 0 && (IsAlnum(content[i-1]) || content[i-1] == '_')
}

// Base64URLAt reports whether content has a URL-safe base64 byte at i; false
// past the end. Used to reject candidates that continue into a longer key.
func Base64URLAt(content []byte, i int) bool {
	return i < len(content) && IsBase64URL(content[i])
}

// Span returns the length of the run of bytes starting at content[start]
// that satisfy ok, at most limit bytes.
func Span(content []byte, start, limit int, ok func(byte) bool) int {
	n := 0
	for start+n < len(content) && n < limit && ok(content[start+n]) {
		n++
	}
	return n
}

// ReadBody reads at most limit bytes of a response body.
func ReadBody(r io.Reader, limit int64) []byte {
	body, _ := io.ReadAll(io.LimitReader(r, limit))
	return body
}

// Do sends the request with patty's User-Agent set.
func Do(client *http.Client, req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", UserAgent)
	return client.Do(req)
}

// HintMatches reports whether a partially redacted credential, the head and
// tail of the value around an ellipsis as providers list their keys
// (`sk-ant-api03-R2D…igAA`, `sk-abc...def`), fits the full value. A hint
// without an ellipsis or without a tail never matches: the head alone is
// usually just the prefix every key shares.
func HintMatches(hint, value string) bool {
	head, tail, ok := strings.Cut(hint, "…")
	if !ok {
		head, tail, ok = strings.Cut(hint, "...")
	}
	if !ok || tail == "" || len(value) < len(head)+len(tail) {
		return false
	}
	return strings.HasPrefix(value, head) && strings.HasSuffix(value, tail)
}
