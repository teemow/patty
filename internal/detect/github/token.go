package github

import (
	"hash/crc32"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindPAT is a classic personal access token (ghp_).
	KindPAT detect.Kind = "github-pat"
	// KindOAuth is an OAuth app access token (gho_).
	KindOAuth detect.Kind = "github-oauth"
	// KindUserToServer is a GitHub App user-to-server token (ghu_).
	KindUserToServer detect.Kind = "github-user-to-server"
	// KindServerToServer is a GitHub App installation token (ghs_).
	KindServerToServer detect.Kind = "github-server-to-server"
	// KindRefresh is a GitHub App refresh token (ghr_).
	KindRefresh detect.Kind = "github-refresh"
	// KindFineGrained is a fine-grained personal access token (github_pat_).
	KindFineGrained detect.Kind = "github-fine-grained-pat"
)

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
var classicKinds = map[byte]detect.Kind{
	'p': KindPAT,
	'o': KindOAuth,
	'u': KindUserToServer,
	's': KindServerToServer,
	'r': KindRefresh,
}

// Find implements detect.Provider.
//
// Two substring passes cover all six families: one for the shared "gh"
// stem of the classic prefixes and one for "github_pat_". Every candidate
// is then checked for exact shape and (classic families) checksum.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	found = detect.ScanPrefix(found, content, "gh", func(start int) (detect.Token, bool) {
		if start+3 >= len(content) || content[start+3] != '_' {
			return detect.Token{}, false
		}
		kind, ok := classicKinds[content[start+2]]
		if !ok {
			return detect.Token{}, false
		}
		return classicAt(content, start, kind)
	})
	return detect.ScanPrefix(found, content, fineGrainedPrefix, func(start int) (detect.Token, bool) {
		return fineGrainedAt(content, start)
	})
}

func classicAt(content []byte, start int, kind detect.Kind) (detect.Token, bool) {
	end := start + classicLen
	if end > len(content) || !detect.All(content[start+4:end], detect.IsAlnum) || detect.AlnumAt(content, end) {
		return detect.Token{}, false
	}
	random := string(content[start+4 : end-checksumLen])
	if string(content[end-checksumLen:end]) != Checksum(random) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: kind, Value: string(content[start:end]), Offset: start, ChecksumVerified: true}, true
}

func fineGrainedAt(content []byte, start int) (detect.Token, bool) {
	end := start + fineGrainedLen
	idStart := start + len(fineGrainedPrefix)
	sep := idStart + fineGrainedIDLen
	if end > len(content) || content[sep] != '_' ||
		!detect.All(content[idStart:sep], detect.IsAlnum) || !detect.All(content[sep+1:end], detect.IsAlnum) ||
		detect.AlnumAt(content, end) || (end < len(content) && content[end] == '_') {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindFineGrained, Value: string(content[start:end]), Offset: start}, true
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
