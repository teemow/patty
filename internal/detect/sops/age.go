package sops

import (
	"strings"

	"filippo.io/age"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindAge is an age X25519 identity (AGE-SECRET-KEY-1…), the private
	// half of an age1… recipient.
	KindAge detect.Kind = "age-identity"
	// KindPGP is an armored PGP private key block, named by the fingerprint
	// of its primary key.
	KindPGP detect.Kind = "pgp-private-key"
)

const (
	agePrefix  = "AGE-SECRET-KEY-1"
	ageBodyLen = 58 // Bech32 data and checksum characters after the prefix
	ageLen     = len(agePrefix) + ageBodyLen
	// bech32Upper is the Bech32 alphabet as an identity is written: age
	// requires one case throughout, and the prefix fixes it to upper case.
	bech32Upper = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
)

// Find implements detect.Provider: one substring pass for the age prefix
// and one for the PGP armor header.
func (*Provider) Find(content []byte) []detect.Token {
	found := detect.ScanPrefix(nil, content, agePrefix, func(start int) (detect.Token, bool) { return ageAt(content, start) })
	return findPGP(found, content)
}

// ageAt checks the exact shape at start and then the Bech32 checksum by
// parsing the identity. A string that fails the checksum is not an identity
// and is not reported, like a classic GitHub token with a wrong CRC.
func ageAt(content []byte, start int) (detect.Token, bool) {
	end := start + ageLen
	if end > len(content) || (start > 0 && detect.IsAlnum(content[start-1])) || detect.AlnumAt(content, end) {
		return detect.Token{}, false
	}
	if !detect.All(content[start+len(agePrefix):end], isBech32Upper) {
		return detect.Token{}, false
	}
	value := string(content[start:end])
	recipient, ok := Recipient(value)
	if !ok {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindAge, Value: value, Offset: start, ChecksumVerified: true, Attribution: "recipient " + recipient}, true
}

// Recipient derives the public key (age1…) of an identity, which is what a
// .sops.yaml lists and is not secret. It reports false when the identity
// does not parse, which means its checksum failed.
func Recipient(identity string) (string, bool) {
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		return "", false
	}
	return id.Recipient().String(), true
}

func isBech32Upper(c byte) bool { return strings.IndexByte(bech32Upper, c) >= 0 }
