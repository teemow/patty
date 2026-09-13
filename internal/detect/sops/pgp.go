package sops

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/teemow/patty/internal/detect"
)

// The armor markers are assembled here rather than written out, so that no
// file of this repository contains one: secret scanners, patty's own CI
// included, key on the literal.
var (
	dashes   = strings.Repeat("-", 5)
	pgpBegin = []byte(dashes + "BEGIN " + openpgp.PrivateKeyType + dashes)
	pgpEnd   = []byte(dashes + "END " + openpgp.PrivateKeyType + dashes)
)

// pgpMaxBlock bounds the search for the end marker; a key block with
// several subkeys is a few kilobytes.
const pgpMaxBlock = 1 << 20

// findPGP appends one token per private key in every armored private key
// block of content. A block that does not parse is not a key and is not
// reported; a block that parses had its packet structure and self
// signatures checked, which is more than a checksum.
func findPGP(found []detect.Token, content []byte) []detect.Token {
	for idx := 0; ; {
		i := bytes.Index(content[idx:], pgpBegin)
		if i < 0 {
			return found
		}
		start := idx + i
		limit := min(len(content), start+pgpMaxBlock)
		j := bytes.Index(content[start:limit], pgpEnd)
		if j < 0 {
			idx = start + len(pgpBegin)
			continue
		}
		stop := start + j + len(pgpEnd)
		found = append(found, pgpKeys(content[start:stop], start)...)
		idx = stop
	}
}

func pgpKeys(block []byte, offset int) []detect.Token {
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(block))
	if err != nil {
		return nil
	}
	var out []detect.Token
	for _, e := range ring {
		if e.PrivateKey == nil {
			continue
		}
		fp := Fingerprint(e.PrimaryKey)
		out = append(out, detect.Token{Kind: KindPGP, Value: fp, Offset: offset, ChecksumVerified: true, Attribution: describe(e, fp), Encrypted: protected(e)})
	}
	return out
}

// Fingerprint renders a key's fingerprint the way gpg and sops write it:
// upper-case hex, forty characters for a version 4 key.
func Fingerprint(key *packet.PublicKey) string {
	return strings.ToUpper(hex.EncodeToString(key.Fingerprint))
}

// describe says whose key it is and whether the secret material is
// passphrase-protected. A protected key is a smaller leak: it is useless
// without the passphrase, as long as that was not committed next to it.
func describe(e *openpgp.Entity, fp string) string {
	parts := []string{"fingerprint " + fp}
	if id := e.PrimaryIdentity(); id != nil && id.Name != "" {
		parts = append(parts, id.Name)
	}
	if protected(e) {
		parts = append(parts, "passphrase-protected")
	} else {
		parts = append(parts, "not passphrase-protected")
	}
	return strings.Join(parts, ", ")
}

// protected reports whether every secret key of the entity is encrypted. A
// single plaintext subkey is enough to decrypt with, so a mixed key counts
// as unprotected. Dummy keys (gpg stubs for material kept elsewhere) hold
// no secret and are ignored.
func protected(e *openpgp.Entity) bool {
	keys := []*packet.PrivateKey{e.PrivateKey}
	for _, sk := range e.Subkeys {
		keys = append(keys, sk.PrivateKey)
	}
	secret := false
	for _, k := range keys {
		if k == nil || k.Dummy() {
			continue
		}
		if !k.Encrypted {
			return false
		}
		secret = true
	}
	return secret
}
