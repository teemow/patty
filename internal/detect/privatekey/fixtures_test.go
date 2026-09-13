package privatekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Every key, certificate and armored block these tests use is generated
// at run time, so that no file of the repository holds one.

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// openssh renders a key in OpenSSH format, encrypted when passphrase is set.
func openssh(t *testing.T, key crypto.PrivateKey, comment, passphrase string) string {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, comment)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, comment, []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

func pkcs8(t *testing.T, key crypto.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: labelPKCS8, Bytes: der}))
}

func pkcs1(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: labelRSA, Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func sec1(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: labelEC, Bytes: der}))
}

// legacyEncrypted renders a PKCS#1 key with the Proc-Type/DEK-Info
// headers openssl writes for a passphrase-protected legacy key.
func legacyEncrypted(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	block, err := x509.EncryptPEMBlock(rand.Reader, labelRSA, x509.MarshalPKCS1PrivateKey(key), []byte("passphrase"), x509.PEMCipherAES256) //nolint:staticcheck // that is the legacy format under test
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}

// pkcs8Encrypted renders an ENCRYPTED PRIVATE KEY block; the body is
// random, which is all the detector reads of it.
func pkcs8Encrypted(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: labelPKCS8Encrypted, Bytes: randomBytes(t, 200)}))
}

// cosignKey renders the block cosign writes: a JSON document with the
// KDF, the cipher and a secretbox, base64 in the sigstore armor.
func cosignKey(t *testing.T) string {
	t.Helper()
	doc := map[string]any{
		"kdf":        map[string]any{"name": "scrypt", "params": map[string]int{"N": 32768, "r": 8, "p": 1}, "salt": base64.StdEncoding.EncodeToString(randomBytes(t, 32))},
		"cipher":     map[string]any{"name": "nacl/secretbox", "nonce": base64.StdEncoding.EncodeToString(randomBytes(t, 24))},
		"ciphertext": base64.StdEncoding.EncodeToString(randomBytes(t, 48)),
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: labelSigstore, Bytes: raw}))
}

func publicPEM(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: labelPublicKey, Bytes: der}))
}

// authorizedLine renders a public key the way authorized_keys and .pub
// files carry it.
func authorizedLine(t *testing.T, pub crypto.PublicKey, comment string) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return line
}

func fingerprint(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(sshPub)
}

func spki(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return spkiHash(der)
}

// certificate issues a certificate for pub with the given names, signed
// by parent (self-signed when parent is nil).
func certificate(t *testing.T, pub crypto.PublicKey, cn string, dnsNames []string, notAfter time.Time, ca bool, parent *x509.Certificate, signer crypto.Signer) (string, *x509.Certificate) {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		NotBefore:             notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:              notAfter,
		IsCA:                  ca,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if len(dnsNames) > 0 {
		tmpl.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: labelCertificate, Bytes: der})), cert
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// escaped renders a block the way a JSON or Terraform string carries it.
func escaped(block string) string {
	return strings.ReplaceAll(strings.TrimSuffix(block, "\n"), "\n", `\n`)
}

// indented renders a block as a YAML block scalar.
func indented(block string) string {
	var b strings.Builder
	for line := range strings.Lines(block) {
		b.WriteString("    " + line)
	}
	return b.String()
}
