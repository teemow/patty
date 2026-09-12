package aws

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindAccessKey is the long-lived access key of an IAM user (AKIA, and
	// the older ABIA, ACCA and A3T prefixes).
	KindAccessKey detect.Kind = "aws-access-key"
	// KindTemporaryKey is a temporary access key issued by STS (ASIA), valid
	// only together with its session token and for a few hours.
	KindTemporaryKey detect.Kind = "aws-temporary-access-key"
)

const (
	prefixLen = 4
	keyLen    = 20 // prefix + 16 base32 characters
	secretLen = 40 // a secret access key is 30 random bytes in base64
	// sessionMin is the shortest run of base64 taken for a session token;
	// real ones are several hundred characters.
	sessionMin = 100
	// keywordWindow is how far back on its line a candidate secret is
	// checked for the word that names it.
	keywordWindow = 48
	// accountMask selects the account id from the first 48 bits of a key
	// id's body: forty bits behind a sign bit, shifted left by seven.
	accountMask  = 0x7fffffffff80
	accountShift = 7
)

// prefixes start every key id. "A3T" is followed by one more letter or
// digit; the others are complete.
var prefixes = []string{"AKIA", "ASIA", "ABIA", "ACCA", "A3T"}

// Find implements detect.Provider. Five substring passes cover the key id
// prefixes; each candidate is checked for the exact shape (twenty characters
// of the base32 alphabet, not part of a longer word). Every key id found is
// then paired with the secret, and for a temporary key the session token,
// that appears closest to it in the same object.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	for _, prefix := range prefixes {
		found = detect.ScanPrefix(found, content, prefix, func(start int) (detect.Token, bool) { return keyAt(content, start) })
	}
	if len(found) == 0 {
		return nil
	}
	pair(content, found)
	return found
}

func keyAt(content []byte, start int) (detect.Token, bool) {
	end := start + keyLen
	if end > len(content) || (start > 0 && detect.IsAlnum(content[start-1])) || detect.AlnumAt(content, end) {
		return detect.Token{}, false
	}
	if !isUpperAlnum(content[start+prefixLen-1]) || !detect.All(content[start+prefixLen:end], isBase32) {
		return detect.Token{}, false
	}
	kind := KindAccessKey
	if content[start+1] == 'S' {
		kind = KindTemporaryKey
	}
	id := string(content[start:end])
	return detect.Token{Kind: kind, Value: id, Offset: start, Attribution: "account " + Account(id)}, true
}

// Account decodes the twelve-digit account id a key id was issued in. The
// sixteen base32 characters after the prefix decode to ten bytes; the first
// six hold the account id, shifted left by seven bits behind a sign bit.
// Exported so callers and tests can check the attribution.
func Account(keyID string) string {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(keyID[prefixLen:])
	if err != nil || len(raw) < 6 {
		return ""
	}
	var buf [8]byte
	copy(buf[2:], raw[:6])
	n := binary.BigEndian.Uint64(buf[:])
	return fmt.Sprintf("%012d", (n&accountMask)>>accountShift)
}

// credentials splits a token's companion material into the secret access
// key and, for a temporary key, the session token that follows it.
func credentials(tok detect.Token) (secret, session string) {
	secret, session, _ = strings.Cut(tok.Secret, "\n")
	return secret, session
}

// companion is a run of base64 text in the object that could be the secret
// access key or the session token of a key id.
type companion struct {
	start, end int
	// keyword reports whether the run is preceded on its line by the word
	// that names it: "secret" (aws_secret_access_key, SecretAccessKey,
	// secret_key) or "session" (aws_session_token, SessionToken).
	keyword bool
}

// pair gives every key id the secret and session token found closest to
// it, and says in the attribution what was found.
func pair(content []byte, keys []detect.Token) {
	secrets, sessions := companions(content)
	for i := range keys {
		k := &keys[i]
		secret := nearest(content, *k, secrets)
		switch {
		case secret == "":
			k.Attribution += ", key id only, secret not found nearby"
		case k.Kind != KindTemporaryKey:
			k.Secret = secret
			k.Attribution += ", key pair"
		default:
			k.Secret = secret
			if session := nearest(content, *k, sessions); session != "" {
				k.Secret += "\n" + session
				k.Attribution += ", key pair with session token"
			} else {
				k.Attribution += ", key pair, session token not found nearby"
			}
		}
	}
}

// companions collects the maximal runs of base64 characters in content
// that have the shape of a secret access key (exactly forty characters, of
// mixed case and not all hexadecimal, which rules out git object ids) or of
// a session token (at least sessionMin characters plus base64 padding).
func companions(content []byte) (secrets, sessions []companion) {
	for i := 0; i < len(content); {
		if !isBase64(content[i]) {
			i++
			continue
		}
		start := i
		for i < len(content) && isBase64(content[i]) {
			i++
		}
		switch run := content[start:i]; {
		case len(run) == secretLen && plausibleSecret(run):
			secrets = append(secrets, companion{start, i, hasKeyword(content, start, "secret")})
		case len(run) >= sessionMin:
			for i < len(content) && content[i] == '=' {
				i++
			}
			sessions = append(sessions, companion{start, i, hasKeyword(content, start, "session")})
		}
	}
	return secrets, sessions
}

func plausibleSecret(run []byte) bool {
	return !detect.All(run, func(c byte) bool { return !isUpper(c) }) &&
		!detect.All(run, func(c byte) bool { return !isLower(c) }) &&
		!detect.All(run, detect.IsHex)
}

// hasKeyword reports whether word appears, in any case, in the last
// keywordWindow bytes of the line before position start.
func hasKeyword(content []byte, start int, word string) bool {
	from := max(bytes.LastIndexByte(content[:start], '\n')+1, start-keywordWindow)
	return bytes.Contains(bytes.ToLower(content[from:start]), []byte(word))
}

// nearest picks the candidate that most likely belongs to the key: one
// named by its keyword first, then one on the key's own line or the line
// after it, then the closest, with candidates after the key preferred over
// those before it.
func nearest(content []byte, key detect.Token, cands []companion) string {
	keyEnd := key.Offset + keyLen
	best, bestRank := -1, [3]int{}
	for i, c := range cands {
		var r [3]int
		if c.keyword {
			r[0] = 1
		}
		if c.start >= keyEnd {
			if bytes.Count(content[keyEnd:c.start], []byte{'\n'}) <= 1 {
				r[1] = 1
			}
			r[2] = -(c.start - keyEnd)
		} else {
			r[2] = -2 * (key.Offset - c.end)
		}
		if best < 0 || r[0] > bestRank[0] || r[0] == bestRank[0] && (r[1] > bestRank[1] || r[1] == bestRank[1] && r[2] > bestRank[2]) {
			best, bestRank = i, r
		}
	}
	if best < 0 {
		return ""
	}
	return string(content[cands[best].start:cands[best].end])
}

func isBase32(c byte) bool     { return (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') }
func isUpper(c byte) bool      { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool      { return c >= 'a' && c <= 'z' }
func isUpperAlnum(c byte) bool { return isUpper(c) || detect.IsDigit(c) }
func isBase64(c byte) bool     { return detect.IsAlnum(c) || c == '/' || c == '+' }
