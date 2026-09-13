package kubernetes

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"
)

// certificate is a parsed client certificate with its private key.
type certificate struct {
	// Fingerprint is the hex SHA-256 of the certificate's DER bytes, the
	// value `openssl x509 -fingerprint -sha256` prints without colons.
	Fingerprint string
	Subject     string
	Groups      []string
	Issuer      string
	NotAfter    time.Time
	PEM, KeyPEM string
}

// parseCertificate decodes the base64 PEM pair a kubeconfig embeds. The
// key has to belong to the certificate: a certificate without its key is
// not a credential.
func parseCertificate(certData, keyData string) (certificate, bool) {
	certPEM, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certData))
	if err != nil {
		return certificate{}, false
	}
	keyPEM, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyData))
	if err != nil {
		return certificate{}, false
	}
	return parsePEM(certPEM, keyPEM)
}

func parsePEM(certPEM, keyPEM []byte) (certificate, bool) {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return certificate{}, false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return certificate{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certificate{}, false
	}
	sum := sha256.Sum256(cert.Raw)
	return certificate{
		Fingerprint: hex.EncodeToString(sum[:]),
		Subject:     cert.Subject.CommonName,
		Groups:      cert.Subject.Organization,
		Issuer:      cert.Issuer.CommonName,
		NotAfter:    cert.NotAfter,
		PEM:         string(certPEM),
		KeyPEM:      string(keyPEM),
	}, true
}

// Expired reports whether the certificate's validity has ended.
func (c certificate) Expired() bool { return c.NotAfter.Before(time.Now()) }

// String is the attribution: who the certificate identifies, to whom, and
// until when. Groups are what RBAC binds; system:masters is the one that
// matters most.
func (c certificate) String() string {
	s := "CN=" + c.Subject
	if len(c.Groups) > 0 {
		s += " groups=" + strings.Join(c.Groups, ",")
	}
	if c.Issuer != "" {
		s += " issuer " + c.Issuer
	}
	return s + expiry(c.NotAfter)
}
