package kubernetes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Everything a test needs is minted at runtime: certificates, keys, tokens
// and manifests, so no credential-shaped literal is committed.

// authority is a throwaway CA that signs client certificates.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  []byte
}

func newAuthority(t *testing.T, name string) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &authority{cert: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// client issues a client certificate with its key, both PEM.
func (a *authority) client(t *testing.T, cn string, groups []string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	notBefore := time.Now().Add(-time.Hour)
	if notAfter.Before(notBefore) {
		notBefore = notAfter.Add(-48 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: groups},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// kubeconfig renders a kubeconfig with one cluster and one context per
// user; users are the YAML snippets the *User helpers render.
func kubeconfig(server string, caPEM []byte, insecure bool, users ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\npreferences: {}\nclusters:\n- name: test\n  cluster:\n    server: " + server + "\n")
	if caPEM != nil {
		b.WriteString("    certificate-authority-data: " + b64(caPEM) + "\n")
	}
	if insecure {
		b.WriteString("    insecure-skip-tls-verify: true\n")
	}
	b.WriteString("contexts:\n")
	for _, u := range users {
		name := strings.TrimPrefix(strings.SplitN(u, "\n", 2)[0], "- name: ")
		b.WriteString("- name: " + name + "@test\n  context:\n    cluster: test\n    user: " + name + "\n")
	}
	b.WriteString("current-context: default\nusers:\n")
	for _, u := range users {
		b.WriteString(u)
	}
	return b.String()
}

func certUser(name string, certPEM, keyPEM []byte) string {
	return "- name: " + name + "\n  user:\n    client-certificate-data: " + b64(certPEM) + "\n    client-key-data: " + b64(keyPEM) + "\n"
}

func tokenUser(name, token string) string {
	return "- name: " + name + "\n  user:\n    token: " + token + "\n"
}

func basicUser(name, username, password string) string {
	return "- name: " + name + "\n  user:\n    username: " + username + "\n    password: " + password + "\n"
}

func execUser(name string) string {
	return "- name: " + name + "\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [eks, get-token]\n    client-certificate: /home/me/.kube/client.crt\n    client-key: /home/me/.kube/client.key\n    tokenFile: /var/run/token\n"
}

// mintJWT signs claims at runtime with a throwaway key.
func mintJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	signing := enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// legacyToken is a service account token as Kubernetes issued them before
// bound tokens: no expiry, flat claims.
func legacyToken(t *testing.T, ns, name string) string {
	return mintJWT(t, map[string]any{
		"iss":                                    "kubernetes/serviceaccount",
		"kubernetes.io/serviceaccount/namespace": ns,
		"kubernetes.io/serviceaccount/secret.name":          name + "-token-abcde",
		"kubernetes.io/serviceaccount/service-account.name": name,
		"kubernetes.io/serviceaccount/service-account.uid":  "0d1e2f3a",
		"sub": "system:serviceaccount:" + ns + ":" + name,
	})
}

// boundToken is a projected service account token tied to a pod.
func boundToken(t *testing.T, ns, name, pod string, exp time.Time) string {
	return mintJWT(t, map[string]any{
		"aud": []string{"https://kubernetes.default.svc.cluster.local"},
		"exp": exp.Unix(),
		"iat": exp.Add(-time.Hour).Unix(),
		"iss": "https://kubernetes.default.svc.cluster.local",
		"kubernetes.io": map[string]any{
			"namespace":      ns,
			"pod":            map[string]any{"name": pod, "uid": "1a2b3c"},
			"serviceaccount": map[string]any{"name": name, "uid": "4d5e6f"},
		},
		"nbf": exp.Add(-time.Hour).Unix(),
		"sub": "system:serviceaccount:" + ns + ":" + name,
	})
}

// manifest renders a Secret manifest; data values are base64-encoded here.
func manifest(ns, name string, data, stringData map[string]string, extra string) string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: " + "Secret\nmetadata:\n  name: " + name + "\n")
	if ns != "" {
		b.WriteString("  namespace: " + ns + "\n")
	}
	b.WriteString(extra)
	if len(data) > 0 {
		b.WriteString("data:\n")
		for k, v := range data {
			b.WriteString("  " + k + ": " + b64([]byte(v)) + "\n")
		}
	}
	if len(stringData) > 0 {
		b.WriteString("stringData:\n")
		for k, v := range stringData {
			b.WriteString("  " + k + ": " + v + "\n")
		}
	}
	return b.String()
}
