package sops

import (
	"bytes"
	"strings"

	"filippo.io/age"

	"github.com/teemow/patty/internal/detect"
)

const (
	recipientPrefix  = "age1"
	recipientBodyLen = 58
	// bech32Lower is the alphabet of a recipient, which age writes in lower case.
	bech32Lower = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	// fingerprintLen is the hex length of a version 4 PGP fingerprint, the
	// form .sops.yaml and the sops metadata use.
	fingerprintLen = 40
)

// Observe implements detect.Correlator. It returns the recipients and PGP
// fingerprints an object lists when the object is sops material: the
// creation rules of a .sops.yaml, or an encrypted file, recognisable by its
// ENC[…] values or its sops metadata block. Anything else costs a few
// substring searches and returns nil; the identity file itself, which
// names its own public key in a comment, is not sops material.
func (*Provider) Observe(content []byte) []detect.Sighting {
	if !sopsMaterial(content) {
		return nil
	}
	var ids []string
	ids = recipients(ids, content)
	if bytes.Contains(content, []byte("pgp")) {
		ids = fingerprints(ids, content)
	}
	return detect.Sightings(ids)
}

// Identifiers implements detect.Correlator: the public key of an age
// identity, the fingerprint of a PGP key.
func (*Provider) Identifiers(tok detect.Token) []string {
	switch tok.Kind {
	case KindAge:
		if recipient, ok := Recipient(tok.Value); ok {
			return []string{recipient}
		}
	case KindPGP:
		return []string{strings.ToUpper(tok.Value)}
	}
	return nil
}

func sopsMaterial(content []byte) bool {
	return bytes.Contains(content, []byte("ENC[")) ||
		bytes.Contains(content, []byte("creation_rules")) ||
		(bytes.Contains(content, []byte("sops:")) && (bytes.Contains(content, []byte("age:")) || bytes.Contains(content, []byte("pgp:"))))
}

// recipients appends every age1… public key in content whose checksum holds.
func recipients(ids []string, content []byte) []string {
	needle := []byte(recipientPrefix)
	for idx := 0; ; {
		i := bytes.Index(content[idx:], needle)
		if i < 0 {
			return ids
		}
		start := idx + i
		idx = start + len(needle)
		end := start + len(recipientPrefix) + recipientBodyLen
		if end > len(content) || (start > 0 && detect.IsAlnum(content[start-1])) || detect.AlnumAt(content, end) {
			continue
		}
		if !detect.All(content[start+len(recipientPrefix):end], isBech32Lower) {
			continue
		}
		if _, err := age.ParseX25519Recipient(string(content[start:end])); err == nil {
			ids = appendUnique(ids, string(content[start:end]))
		}
	}
}

// fingerprints appends every run of exactly forty hexadecimal characters
// that stands on its own, upper-cased as gpg prints it.
func fingerprints(ids []string, content []byte) []string {
	for i := 0; i < len(content); {
		if !detect.IsHex(content[i]) {
			i++
			continue
		}
		start := i
		for i < len(content) && detect.IsAlnum(content[i]) {
			i++
		}
		run := content[start:i]
		if len(run) == fingerprintLen && (start == 0 || !detect.IsAlnum(content[start-1])) && detect.All(run, detect.IsHex) {
			ids = appendUnique(ids, strings.ToUpper(string(run)))
		}
	}
	return ids
}

func appendUnique(ids []string, id string) []string {
	for _, have := range ids {
		if have == id {
			return ids
		}
	}
	return append(ids, id)
}

func isBech32Lower(c byte) bool { return strings.IndexByte(bech32Lower, c) >= 0 }
