// Package detect finds GitHub credentials in arbitrary byte content.
//
// It is built for throughput: a scan is a handful of SIMD-accelerated
// substring searches for the fixed token prefixes followed by an exact
// shape check and, for the classic token families, an offline CRC32
// checksum verification. A well-formed string with a wrong checksum is not a
// token; that single check removes the false positives a regex scanner has
// to live with.
package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash/crc32"
	"sort"
)

// Kind names a GitHub credential family.
type Kind string

const (
	// KindPAT is a classic personal access token (ghp_).
	KindPAT Kind = "github-pat"
	// KindOAuth is an OAuth app access token (gho_).
	KindOAuth Kind = "github-oauth"
	// KindUserToServer is a GitHub App user-to-server token (ghu_).
	KindUserToServer Kind = "github-user-to-server"
	// KindServerToServer is a GitHub App installation token (ghs_).
	KindServerToServer Kind = "github-server-to-server"
	// KindRefresh is a GitHub App refresh token (ghr_).
	KindRefresh Kind = "github-refresh"
	// KindFineGrained is a fine-grained personal access token (github_pat_).
	KindFineGrained Kind = "github-fine-grained-pat"
)

// Token is one credential found in scanned content.
type Token struct {
	Kind  Kind
	Value string
	// Offset is the byte offset of the token in the scanned content.
	Offset int
	// Line is the 1-based line the token starts on.
	Line int
	// ChecksumVerified reports whether the token carries a CRC32 checksum
	// that was verified offline. Classic tokens do; the fine-grained format
	// is matched on shape alone.
	ChecksumVerified bool
}

// Fingerprint returns a short, stable, non-reversible identifier for the
// token value: the first 16 hex characters of its SHA-256. It is safe to put
// in logs and allow-lists.
func (t Token) Fingerprint() string {
	return Fingerprint(t.Value)
}

// Fingerprint returns the fingerprint of a raw token value.
func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

// Redact hides the middle of a token, keeping enough of both ends to
// recognise it (`ghp_AbCd…WxYz`).
func Redact(value string) string {
	const keepHead, keepTail = 8, 4
	if len(value) <= keepHead+keepTail+1 {
		return value
	}
	return value[:keepHead] + "…" + value[len(value)-keepTail:]
}

const (
	classicRandomLen   = 30
	checksumLen        = 6
	classicLen         = 4 + classicRandomLen + checksumLen // prefix + random + checksum
	fineGrainedPrefix  = "github_pat_"
	fineGrainedIDLen   = 22
	fineGrainedBodyLen = 59
	fineGrainedLen     = len(fineGrainedPrefix) + fineGrainedIDLen + 1 + fineGrainedBodyLen
)

// classicKinds maps the type letter of a classic prefix (gh?_) to its kind.
var classicKinds = map[byte]Kind{
	'p': KindPAT,
	'o': KindOAuth,
	'u': KindUserToServer,
	's': KindServerToServer,
	'r': KindRefresh,
}

// Find returns every GitHub token in content, sorted by offset.
//
// Two substring passes cover all six families: one for the shared "gh"
// stem of the classic prefixes and one for "github_pat_". Every candidate
// is then checked for exact shape and (classic families) checksum.
func Find(content []byte) []Token {
	var found []Token
	found = scanPrefix(found, content, "gh", func(start int) (Token, bool) {
		if start+3 >= len(content) || content[start+3] != '_' {
			return Token{}, false
		}
		kind, ok := classicKinds[content[start+2]]
		if !ok {
			return Token{}, false
		}
		return classicAt(content, start, kind)
	})
	found = scanPrefix(found, content, fineGrainedPrefix, func(start int) (Token, bool) {
		return fineGrainedAt(content, start)
	})
	if len(found) == 0 {
		return nil
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Offset < found[j].Offset })
	for i := range found {
		found[i].Line = bytes.Count(content[:found[i].Offset], []byte{'\n'}) + 1
	}
	return found
}

func scanPrefix(found []Token, content []byte, prefix string, at func(start int) (Token, bool)) []Token {
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

func classicAt(content []byte, start int, kind Kind) (Token, bool) {
	end := start + classicLen
	if end > len(content) || !allAlnum(content[start+4:end]) || alnumAt(content, end) {
		return Token{}, false
	}
	random := string(content[start+4 : end-checksumLen])
	if string(content[end-checksumLen:end]) != Checksum(random) {
		return Token{}, false
	}
	return Token{Kind: kind, Value: string(content[start:end]), Offset: start, ChecksumVerified: true}, true
}

func fineGrainedAt(content []byte, start int) (Token, bool) {
	end := start + fineGrainedLen
	idStart := start + len(fineGrainedPrefix)
	sep := idStart + fineGrainedIDLen
	if end > len(content) || content[sep] != '_' ||
		!allAlnum(content[idStart:sep]) || !allAlnum(content[sep+1:end]) ||
		alnumAt(content, end) || (end < len(content) && content[end] == '_') {
		return Token{}, false
	}
	return Token{Kind: KindFineGrained, Value: string(content[start:end]), Offset: start}, true
}

// Checksum computes the 6-character Base62 CRC32 checksum GitHub appends to
// the 30 random characters of a classic token. Exported so callers (and
// tests) can construct well-formed tokens without hard-coding any.
func Checksum(random string) string {
	return base62(crc32.ChecksumIEEE([]byte(random)))
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func base62(n uint32) string {
	var b [checksumLen]byte
	for i := checksumLen - 1; i >= 0; i-- {
		b[i] = base62Alphabet[n%62]
		n /= 62
	}
	return string(b[:])
}

func isAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func allAlnum(b []byte) bool {
	for _, c := range b {
		if !isAlnum(c) {
			return false
		}
	}
	return true
}

func alnumAt(content []byte, i int) bool {
	return i < len(content) && isAlnum(content[i])
}
