package privatekey

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys are still found in the wild and have to be named
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindSSH is a private key in OpenSSH format, or a PEM key found where
	// SSH keys live; its name is the OpenSSH fingerprint of its public key
	// (`SHA256:…`) for the former, the SHA-256 of the SubjectPublicKeyInfo
	// for the latter.
	KindSSH detect.Kind = "ssh-private-key"
	// KindTLS is a PKCS#8, PKCS#1 or SEC1 PEM private key; its name is the
	// hex SHA-256 of its public key's SubjectPublicKeyInfo, or `sha256:` and
	// the hash of the block when the key is encrypted.
	KindTLS detect.Kind = "tls-private-key"
	// KindCosign is the encrypted signing key cosign writes; its name is
	// `sha256:` and the hash of the block, the public key not being
	// derivable.
	KindCosign detect.Kind = "cosign-private-key"
)

// The PEM labels this provider claims. PGP PRIVATE KEY BLOCK is the sops
// provider's; CERTIFICATE and PUBLIC KEY blocks are not credentials.
const (
	labelOpenSSH        = "OPENSSH PRIVATE KEY"
	labelPKCS8          = "PRIVATE KEY"
	labelPKCS8Encrypted = "ENCRYPTED PRIVATE KEY"
	labelRSA            = "RSA PRIVATE KEY"
	labelEC             = "EC PRIVATE KEY"
	labelDSA            = "DSA PRIVATE KEY"
	labelSigstore       = "ENCRYPTED SIGSTORE PRIVATE KEY"
	labelCosign         = "ENCRYPTED COSIGN PRIVATE KEY"
)

// The armor markers are assembled here rather than written out, so that no
// file of this repository contains one: secret scanners, patty's own CI
// included, key on the literal.
var (
	dashes = strings.Repeat("-", 5)
	begin  = []byte(dashes + "BEGIN ")
)

const (
	// maxBlock bounds the search for the end marker; an 8192-bit RSA key
	// is under 7 KiB, a chain of certificates a few tens.
	maxBlock = 1 << 20
	// maxLabel bounds a PEM label.
	maxLabel = 64
	// unencrypted and encrypted are the words of the attribution.
	unencrypted = "unencrypted"
	encrypted   = "encrypted"
)

// Find implements detect.Provider: one substring pass for the armor header,
// then the block up to its matching end marker is parsed. A block that
// does not parse is not a key and is not reported.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	for idx := 0; ; {
		i := bytes.Index(content[idx:], begin)
		if i < 0 {
			return found
		}
		start := idx + i
		idx = start + len(begin)
		if start > 0 && (content[start-1] == '-' || detect.IsAlnum(content[start-1])) {
			continue
		}
		label, ok := labelAt(content, idx)
		if !ok || !claimed(label) {
			continue
		}
		end := []byte(dashes + "END " + label + dashes)
		j := bytes.Index(content[start:min(len(content), start+maxBlock)], end)
		if j < 0 {
			continue
		}
		stop := start + j + len(end)
		if stop < len(content) && content[stop] == '-' {
			continue
		}
		if tok, ok := parse(label, normalize(content[start:stop]), start); ok && !serviceAccountKey(content, start) {
			found = append(found, tok)
		}
		idx = stop
	}
}

// labelAt reads the PEM label that starts at i, up to the closing dashes.
func labelAt(content []byte, i int) (string, bool) {
	rest := content[i:min(len(content), i+maxLabel)]
	j := bytes.Index(rest, []byte(dashes))
	if j <= 0 {
		return "", false
	}
	return string(rest[:j]), true
}

func claimed(label string) bool {
	switch label {
	case labelOpenSSH, labelPKCS8, labelPKCS8Encrypted, labelRSA, labelEC, labelDSA, labelSigstore, labelCosign:
		return true
	}
	return false
}

// normalize turns a block as it stands in the scanned content into the
// form the PEM decoder wants: literal `\n` sequences, the way JSON and
// Terraform strings carry a key, become newlines, indentation (a YAML
// block scalar) and carriage returns go, and every line stands on its
// own. The same key in any of these forms normalizes to the same bytes,
// so it is one finding.
func normalize(raw []byte) []byte {
	raw = bytes.ReplaceAll(raw, []byte(`\r`), nil)
	raw = bytes.ReplaceAll(raw, []byte(`\n`), []byte("\n"))
	raw = bytes.ReplaceAll(raw, []byte("\r"), nil)
	var out bytes.Buffer
	for line := range bytes.Lines(raw) {
		if line = bytes.TrimSpace(line); len(line) > 0 {
			out.Write(line)
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// parse turns one normalized block into a finding. The label says which
// container it is; the container says what the key is.
func parse(label string, block []byte, offset int) (detect.Token, bool) {
	p, _ := pem.Decode(block)
	if p == nil || p.Type != label {
		return detect.Token{}, false
	}
	switch label {
	case labelSigstore, labelCosign:
		return cosignToken(p, block, offset)
	case labelPKCS8Encrypted:
		return detect.Token{Kind: KindTLS, Value: blockHash(block), Offset: offset, Encrypted: true, Attribution: "PKCS#8, " + encrypted + ", algorithm unknown"}, true
	}
	key, err := ssh.ParseRawPrivateKey(block)
	if err == nil {
		return unencryptedToken(label, key, block, offset)
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return detect.Token{}, false
	}
	if missing.PublicKey != nil {
		// The OpenSSH container carries the public key in the clear.
		return detect.Token{Kind: KindSSH, Value: ssh.FingerprintSHA256(missing.PublicKey), Offset: offset, Encrypted: true, Attribution: describeSSH(missing.PublicKey) + ", " + encrypted}, true
	}
	return detect.Token{Kind: kindOf(label), Value: blockHash(block), Offset: offset, Encrypted: true, Attribution: algorithmOf(label) + ", " + encrypted}, true
}

// unencryptedToken names a parsed key by the fingerprint its kind uses and
// keeps the block apart, for the one verification --verify may make.
func unencryptedToken(label string, key any, block []byte, offset int) (detect.Token, bool) {
	pub, alg := publicOf(key)
	if pub == nil {
		return detect.Token{}, false
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return detect.Token{}, false
	}
	tok := detect.Token{Kind: kindOf(label), Offset: offset, Attribution: alg + ", " + unencrypted, Secret: string(block)}
	switch tok.Kind {
	case KindSSH:
		tok.Value = ssh.FingerprintSHA256(sshPub)
		if comment := opensshComment(block); comment != "" {
			tok.Attribution += ", comment " + comment
		}
	default:
		spki, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			// DSA has no PKIX form here; it is an SSH key wherever it lives.
			tok.Kind, tok.Value = KindSSH, ssh.FingerprintSHA256(sshPub)
			return tok, true
		}
		tok.Value = spkiHash(spki)
	}
	return tok, true
}

// kindOf is the kind a container starts out as: OpenSSH and DSA keys are
// SSH keys, every other PEM key is a TLS key until where it lives says
// otherwise (see Classify).
func kindOf(label string) detect.Kind {
	if label == labelOpenSSH || label == labelDSA {
		return KindSSH
	}
	return KindTLS
}

// algorithmOf is what the label of a legacy container says about the key
// when the key itself cannot be read.
func algorithmOf(label string) string {
	switch label {
	case labelRSA:
		return "RSA"
	case labelEC:
		return "ECDSA"
	case labelDSA:
		return "DSA"
	}
	return "PKCS#8"
}

// publicOf derives the public key of a parsed private key and describes
// the algorithm: "RSA 4096", "ECDSA P-256", "ed25519".
func publicOf(key any) (crypto.PublicKey, string) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, "RSA " + strconv.Itoa(k.N.BitLen())
	case *ecdsa.PrivateKey:
		return &k.PublicKey, "ECDSA " + k.Curve.Params().Name
	case *ed25519.PrivateKey:
		return k.Public(), "ed25519"
	case ed25519.PrivateKey:
		return k.Public(), "ed25519"
	case *dsa.PrivateKey:
		return &k.PublicKey, "DSA " + strconv.Itoa(k.P.BitLen())
	}
	return nil, ""
}

// describe names the algorithm of a public key the way publicOf does.
func describe(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA " + strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "ed25519"
	case *dsa.PublicKey:
		return "DSA " + strconv.Itoa(k.P.BitLen())
	}
	return "unknown algorithm"
}

// describeSSH names the algorithm of an SSH public key.
func describeSSH(pub ssh.PublicKey) string {
	if c, ok := pub.(ssh.CryptoPublicKey); ok {
		return describe(c.CryptoPublicKey())
	}
	return pub.Type()
}

// cosignToken is the finding for the encrypted key cosign writes: a JSON
// document naming its KDF and cipher around a secretbox. The public key
// is not in it; the key is named by the hash of the block.
func cosignToken(p *pem.Block, block []byte, offset int) (detect.Token, bool) {
	var doc struct {
		KDF struct {
			Name string `json:"name"`
		} `json:"kdf"`
		Cipher struct {
			Name string `json:"name"`
		} `json:"cipher"`
		Ciphertext string `json:"ciphertext"`
	}
	if json.Unmarshal(p.Bytes, &doc) != nil || doc.Ciphertext == "" {
		return detect.Token{}, false
	}
	attribution := encrypted
	if doc.KDF.Name != "" && doc.Cipher.Name != "" {
		attribution += " with " + doc.KDF.Name + "/" + doc.Cipher.Name
	}
	return detect.Token{Kind: KindCosign, Value: blockHash(block), Offset: offset, Encrypted: true, Attribution: attribution + ", public key not derivable"}, true
}

// spkiHash is the hex SHA-256 of a DER SubjectPublicKeyInfo, what
// `openssl pkey -pubout -outform DER | sha256sum` prints.
func spkiHash(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// blockHash names encrypted material whose public half cannot be read.
func blockHash(block []byte) string {
	sum := sha256.Sum256(block)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// serviceAccountKey reports whether the block at start is the private_key
// of a Google Cloud service account key document, which the Google Cloud
// provider reports as one credential with its account and key id: the
// block sits as a JSON string value under "private_key", escaped once or
// twice, in a document that also names a client_email.
func serviceAccountKey(content []byte, start int) bool {
	i := start - 1
	skip := func(ok func(byte) bool) {
		for i >= 0 && ok(content[i]) {
			i--
		}
	}
	quote := func(c byte) bool { return c == '"' || c == '\\' }
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	skip(quote)
	skip(space)
	if i < 0 || content[i] != ':' {
		return false
	}
	i--
	skip(space)
	skip(quote)
	const field = "private_key"
	if i+1 < len(field) || string(content[i+1-len(field):i+1]) != field {
		return false
	}
	return bytes.Contains(content, []byte("client_email")) && bytes.Contains(content, []byte("service_account"))
}
