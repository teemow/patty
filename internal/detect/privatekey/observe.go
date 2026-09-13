package privatekey

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"path"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"

	"github.com/teemow/patty/internal/detect"
)

// sshTypes are the algorithm names an SSH public key line starts with.
var sshTypes = []string{"ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"}

const (
	labelCertificate = "CERTIFICATE"
	labelPublicKey   = "PUBLIC KEY"
	// publicKeyDetail opens the detail of a PEM public key sighting; the
	// cosign correlation recognises such sightings by it.
	publicKeyDetail = "public key ("
	// maxComment bounds the comment taken from a public key line.
	maxKeyComment = 128
	// maxNames bounds the names listed for a certificate.
	maxNames = 3
)

// Observe implements detect.Correlator. It returns the public halves an
// object names: SSH public keys on their own line (authorized_keys, .pub
// files) or inside a string (Terraform, Ansible, cloud-init), PUBLIC KEY
// blocks (cosign.pub, the keys an image policy pins), and certificates,
// each under the fingerprint forms a private key is named by. Anything
// else costs a few substring searches and returns nil.
func (*Provider) Observe(content []byte) []detect.Sighting {
	var seen []detect.Sighting
	if bytes.Contains(content, []byte("ssh-")) || bytes.Contains(content, []byte("ecdsa-sha2-")) || bytes.Contains(content, []byte("sk-")) {
		seen = sshPublicKeys(seen, content)
	}
	if bytes.Contains(content, begin) {
		seen = pemBlocks(seen, content)
	}
	return seen
}

// Identifiers implements detect.Correlator: a key is known by its name.
func (*Provider) Identifiers(tok detect.Token) []string {
	switch tok.Kind {
	case KindSSH, KindTLS, KindCosign:
		return []string{tok.Value}
	}
	return nil
}

// Adjacent implements detect.ProximityCorrelator: a cosign key says
// nothing about its public half, so it adopts the PEM public key next to
// it, the cosign.pub `cosign generate-key-pair` writes beside cosign.key.
func (*Provider) Adjacent(kind detect.Kind, s detect.Sighting) []string {
	if kind == KindCosign && strings.HasPrefix(s.Detail, publicKeyDetail) {
		return []string{s.ID}
	}
	return nil
}

// Classify implements detect.PathClassifier: a PEM key is an SSH key when
// it lives where SSH keys live (id_*, a .ssh directory) or when an SSH
// public key, in a file or on a GitHub account, names it; a key whose
// public half could not be read stays what its label made it.
func (*Provider) Classify(tok detect.Token, paths []string, matched []string) detect.Kind {
	if tok.Kind != KindTLS || strings.HasPrefix(tok.Value, "sha256:") {
		return ""
	}
	for _, id := range matched {
		if strings.HasPrefix(id, "SHA256:") {
			return KindSSH
		}
	}
	for _, p := range paths {
		base := path.Base(p)
		if (strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub")) || strings.Contains(p, ".ssh/") {
			return KindSSH
		}
	}
	return ""
}

// sshPublicKeys appends every SSH public key in content: an algorithm
// name, the base64 key, and the comment after it up to the end of the
// line or string. A key that does not decode to its named algorithm is
// not a key.
func sshPublicKeys(seen []detect.Sighting, content []byte) []detect.Sighting {
	for _, typ := range sshTypes {
		needle := []byte(typ)
		for idx := 0; ; {
			i := bytes.Index(content[idx:], needle)
			if i < 0 {
				break
			}
			start := idx + i
			idx = start + len(needle)
			if s, ok := sshPublicKeyAt(content, start, typ); ok {
				seen = append(seen, s)
			}
		}
	}
	return seen
}

func sshPublicKeyAt(content []byte, start int, typ string) (detect.Sighting, bool) {
	if start > 0 && (detect.IsAlnum(content[start-1]) || strings.IndexByte("-_.@/", content[start-1]) >= 0) {
		return detect.Sighting{}, false
	}
	i := start + len(typ)
	n := detect.Span(content, i, 16, func(c byte) bool { return c == ' ' || c == '\t' })
	if n == 0 {
		return detect.Sighting{}, false
	}
	i += n
	n = detect.Span(content, i, 1<<16, func(c byte) bool { return detect.IsAlnum(c) || c == '+' || c == '/' || c == '=' })
	if n == 0 || detect.IsAlnum(byteAt(content, i+n)) {
		return detect.Sighting{}, false
	}
	der, err := base64.StdEncoding.DecodeString(string(content[i : i+n]))
	if err != nil {
		return detect.Sighting{}, false
	}
	pub, err := ssh.ParsePublicKey(der)
	if err != nil || pub.Type() != typ {
		return detect.Sighting{}, false
	}
	detail := "ssh public key"
	if comment := lineComment(content, i+n); comment != "" {
		detail += ", comment " + comment
	}
	return detect.Sighting{ID: ssh.FingerprintSHA256(pub), Detail: detail}, true
}

// lineComment reads the comment after a public key: what follows on the
// line, up to a quote or an escape, which end the string a key sits in.
func lineComment(content []byte, i int) string {
	i += detect.Span(content, i, 16, func(c byte) bool { return c == ' ' || c == '\t' })
	n := detect.Span(content, i, maxKeyComment, func(c byte) bool { return c >= 0x20 && c != '"' && c != '\'' && c != '\\' && c != '`' && c != 0x7f })
	return strings.TrimSpace(string(content[i : i+n]))
}

func byteAt(content []byte, i int) byte {
	if i < len(content) {
		return content[i]
	}
	return 0
}

// pemBlocks appends the public key of every PUBLIC KEY and CERTIFICATE
// block in content, under the SubjectPublicKeyInfo hash a TLS key is
// named by. A PUBLIC KEY block also gets the OpenSSH fingerprint form, so
// that a `.pub` written by openssl names an SSH key too; a certificate
// does not, a certificate is never an SSH key.
func pemBlocks(seen []detect.Sighting, content []byte) []detect.Sighting {
	pinned := ""
	pinnedKnown := false
	for idx := 0; ; {
		i := bytes.Index(content[idx:], begin)
		if i < 0 {
			return seen
		}
		start := idx + i
		idx = start + len(begin)
		label, ok := labelAt(content, idx)
		if !ok || (label != labelCertificate && label != labelPublicKey) {
			continue
		}
		end := []byte(dashes + "END " + label + dashes)
		j := bytes.Index(content[start:min(len(content), start+maxBlock)], end)
		if j < 0 {
			continue
		}
		stop := start + j + len(end)
		p, _ := pem.Decode(normalize(content[start:stop]))
		if p == nil || p.Type != label {
			continue
		}
		switch label {
		case labelCertificate:
			if cert, err := x509.ParseCertificate(p.Bytes); err == nil {
				seen = append(seen, detect.Sighting{ID: spkiHash(cert.RawSubjectPublicKeyInfo), Detail: certificateDetail(cert, time.Now())})
			}
		case labelPublicKey:
			pub, err := x509.ParsePKIXPublicKey(p.Bytes)
			if err != nil {
				continue
			}
			if !pinnedKnown {
				pinned, pinnedKnown = pinnedBy(content), true
			}
			seen = append(seen, detect.Sighting{ID: spkiHash(p.Bytes), Detail: publicKeyDetail + describe(pub) + ")" + pinned})
		}
		idx = stop
	}
}

// certificateDetail says what a certificate is for and how long: the
// names it covers, its expiry, and who issued it.
func certificateDetail(cert *x509.Certificate, now time.Time) string {
	var names []string
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	names = append(names, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		names = append(names, u.String())
	}
	if len(names) == 0 && cert.Subject.CommonName != "" {
		names = []string{cert.Subject.CommonName}
	}
	s := "certificate"
	if cert.IsCA {
		s = "CA certificate"
	}
	if len(names) > 0 {
		s += " for " + joinNames(names)
	}
	switch {
	case cert.NotAfter.Before(now):
		s += ", expired " + cert.NotAfter.UTC().Format("2006-01-02")
	default:
		s += ", expires " + cert.NotAfter.UTC().Format("2006-01-02")
	}
	switch issuer := cert.Issuer.CommonName; {
	case bytes.Equal(cert.RawIssuer, cert.RawSubject):
		s += ", self-signed"
	case issuer != "":
		s += ", issuer " + issuer
	case len(cert.Issuer.Organization) > 0:
		s += ", issuer " + cert.Issuer.Organization[0]
	}
	return s
}

func joinNames(names []string) string {
	if len(names) > maxNames {
		return strings.Join(names[:maxNames], ", ") + ", +" + strconv.Itoa(len(names)-maxNames) + " more"
	}
	return strings.Join(names, ", ")
}

// pinnedBy says which image policy a PUBLIC KEY block in content belongs
// to: a Kyverno ClusterPolicy or Policy with verifyImages rules, or a
// sigstore policy-controller ClusterImagePolicy. "" for any other file.
func pinnedBy(content []byte) string {
	kyverno := bytes.Contains(content, []byte("verifyImages")) && (detect.HasKind(content, "ClusterPolicy") || detect.HasKind(content, "Policy"))
	if !kyverno && !detect.HasKind(content, "ClusterImagePolicy") {
		return ""
	}
	for _, doc := range detect.Documents(content) {
		root, ok := doc.Parse()
		if !ok {
			continue
		}
		if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
			root = root.Content[0]
		}
		if root.Kind != yaml.MappingNode {
			continue
		}
		kind := detect.Scalar(root, "kind")
		switch kind {
		case "ClusterPolicy", "Policy", "ClusterImagePolicy":
		default:
			continue
		}
		name := ""
		if meta := detect.Child(root, "metadata"); meta != nil && meta.Kind == yaml.MappingNode {
			name = detect.Scalar(meta, "name")
		}
		s := ", pinned by " + kind
		if kind != "ClusterImagePolicy" {
			s = ", pinned by Kyverno " + kind
		}
		if name != "" {
			s += " " + name
		}
		return s
	}
	return ""
}
