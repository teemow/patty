// Package detect finds credentials in arbitrary byte content and knows, per
// provider, how to verify and revoke them.
//
// The scan is built for throughput: every provider does a handful of
// SIMD-accelerated substring searches for its fixed token prefixes followed
// by an exact shape check and, where the format allows it, an offline
// checksum. A well-formed string with a wrong checksum is not a token; that
// single check removes the false positives a regex scanner has to live with.
//
// The shared vocabulary lives here: Kind, Token, Verification and the
// Provider interface. The providers themselves are sub-packages, assembled
// into a Registry by package providers.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Kind names one credential family of one provider, such as a classic
// GitHub personal access token or a Slack bot token.
type Kind string

// Token is one credential found in scanned content.
type Token struct {
	Kind  Kind
	Value string
	// Offset is the byte offset of the token in the scanned content.
	Offset int
	// Line is the 1-based line the token starts on.
	Line int
	// ChecksumVerified reports whether the token carries a checksum that
	// was verified offline. Classic GitHub tokens do; every other format is
	// matched on shape alone.
	ChecksumVerified bool
	// Attribution is what the token's own shape says about its owner, without
	// contacting the provider: a team id in a Slack token, for example. Empty
	// when the format carries nothing of the sort.
	Attribution string
	// Encrypted reports that the material is passphrase-protected and so
	// useless to whoever found it unless the passphrase leaked with it: an
	// encrypted private key. The report lists such findings after the ones
	// that are usable as they are.
	Encrypted bool
	// Secret is the material a credential needs besides Value when it is made
	// of several strings: the secret access key found next to an AWS key id,
	// and the session token of a temporary one. Its layout is the provider's
	// business. Value alone identifies the credential; Secret is never
	// printed, logged or fingerprinted.
	Secret string
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

// Redact hides the middle of a credential, keeping enough of both ends to
// recognise it (`ghp_AbCd…WxYz`). A URL keeps its path up to the last
// segment, which is the secret part of a webhook (`https://…/T…/B…/Ab…Yz`).
func Redact(value string) string {
	if strings.HasPrefix(value, "http") {
		if i := strings.LastIndexByte(value, '/'); i > 0 {
			return value[:i+1] + redactMiddle(value[i+1:], 2, 4)
		}
	}
	return redactMiddle(value, 8, 4)
}

func redactMiddle(value string, keepHead, keepTail int) string {
	if len(value) <= keepHead+keepTail+1 {
		return value
	}
	return value[:keepHead] + "…" + value[len(value)-keepTail:]
}
