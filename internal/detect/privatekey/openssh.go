package privatekey

import (
	"encoding/binary"
	"encoding/pem"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// opensshMagic opens the openssh-key-v1 container.
const opensshMagic = "openssh-key-v1\x00"

// maxComment bounds the comment looked for at the end of a key.
const maxComment = 1024

// opensshComment reads the comment `ssh-keygen -C` stored in an
// unencrypted OpenSSH private key, which the ssh package does not expose:
// the private section ends with the comment, as a length-prefixed string,
// followed by the padding bytes 1, 2, 3, … up to the cipher's block size.
// An encrypted key, or any layout that does not fit, yields "".
func opensshComment(block []byte) string {
	p, _ := pem.Decode(block)
	if p == nil || p.Type != labelOpenSSH || len(p.Bytes) < len(opensshMagic) || string(p.Bytes[:len(opensshMagic)]) != opensshMagic {
		return ""
	}
	var env struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}
	if ssh.Unmarshal(p.Bytes[len(opensshMagic):], &env) != nil || env.CipherName != "none" {
		return ""
	}
	priv := trimPadding(env.PrivKeyBlock)
	for n := 0; n <= maxComment && n+4 <= len(priv); n++ {
		at := len(priv) - n - 4
		if binary.BigEndian.Uint32(priv[at:]) != uint32(n) { //nolint:gosec // n is bounded by maxComment
			continue
		}
		comment := string(priv[at+4:])
		if utf8.ValidString(comment) && printable(comment) {
			return comment
		}
	}
	return ""
}

// trimPadding removes the sequential padding bytes an OpenSSH private
// section ends with: the last byte says how many there are.
func trimPadding(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n == 0 || n > 16 || n > len(b) {
		return b
	}
	for k := 1; k <= n; k++ {
		if int(b[len(b)-k]) != n-k+1 {
			return b
		}
	}
	return b[:len(b)-n]
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
