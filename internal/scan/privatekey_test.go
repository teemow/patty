package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/privatekey"
	"github.com/teemow/patty/internal/gitrepo"
)

// privateKeyFixture is a repository with every kind of key the provider
// knows, each next to what names it: an OpenSSH deploy key whose public
// half sits in a .pub file, authorized_keys and a Terraform resource; a
// PKCS#1 key under id_rsa; a TLS key with its certificate; a cosign key
// with its cosign.pub and a Kyverno policy pinning it; and an encrypted
// key. The one commit is authored from a GitHub noreply address.
type privateKeyFixture struct {
	dir                           string
	deploy, encrypted             ed25519.PrivateKey
	legacy                        *ecdsa.PrivateKey
	tls, cosign                   *ecdsa.PrivateKey
	deployFP, tlsSPKI, cosignSPKI string
}

func newPrivateKeyFixture(t *testing.T) privateKeyFixture {
	t.Helper()
	f := privateKeyFixture{dir: t.TempDir()}
	f.deploy, f.encrypted = genEd25519(t), genEd25519(t)
	f.legacy, f.tls, f.cosign = genECDSA(t), genECDSA(t), genECDSA(t)
	f.deployFP = sshFingerprint(t, f.deploy.Public())
	f.tlsSPKI = spkiOf(t, f.tls.Public())
	f.cosignSPKI = spkiOf(t, f.cosign.Public())

	must(t, os.MkdirAll(filepath.Join(f.dir, "deploy"), 0o755))
	must(t, os.MkdirAll(filepath.Join(f.dir, "tls"), 0o755))
	must(t, os.MkdirAll(filepath.Join(f.dir, "signing"), 0o755))
	must(t, os.MkdirAll(filepath.Join(f.dir, "policies"), 0o755))
	git(t, f.dir, "init", "-q", "-b", "main")

	pub := authorized(t, f.deploy.Public())
	write(t, filepath.Join(f.dir, "deploy", "id_ed25519"), opensshPEM(t, f.deploy, "deploy@ci", ""))
	write(t, filepath.Join(f.dir, "deploy", "id_ed25519.pub"), pub+" deploy@ci\n")
	write(t, filepath.Join(f.dir, "authorized_keys"), "# ci\n"+pub+" deploy@ci\n")
	write(t, filepath.Join(f.dir, "infra.tf"), "resource \"github_repository_deploy_key\" \"ci\" {\n  key = \""+pub+"\"\n}\n")
	write(t, filepath.Join(f.dir, "deploy", "id_ecdsa"), sec1PEM(t, f.legacy))
	write(t, filepath.Join(f.dir, "tls", "server.key"), pkcs8PEM(t, f.tls))
	write(t, filepath.Join(f.dir, "tls", "server.crt"), certPEM(t, f.tls, "www.example.com"))
	write(t, filepath.Join(f.dir, "signing", "cosign.key"), cosignPEM(t))
	cosignPub := pkixPEM(t, f.cosign.Public())
	write(t, filepath.Join(f.dir, "signing", "cosign.pub"), cosignPub)
	write(t, filepath.Join(f.dir, "policies", "verify.yaml"), "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: verify-images\nspec:\n  rules:\n    - name: check\n      verifyImages:\n        - attestors:\n            - entries:\n                - keys:\n                    publicKeys: |-\n"+indent(cosignPub, 22)+"\n")
	write(t, filepath.Join(f.dir, "backup.key"), opensshPEM(t, f.encrypted, "", "hunter2"))
	git(t, f.dir, "add", ".")
	git(t, f.dir, "commit", "-q", "-m", "add keys", "--author=Octo Cat <12345+octocat@users.noreply.github.com>")
	return f
}

func TestRepoCorrelatesPrivateKeys(t *testing.T) {
	ctx := context.Background()
	f := newPrivateKeyFixture(t)
	repo, err := gitrepo.Open(ctx, f.dir)
	must(t, err)
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/octocat.keys" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(authorized(t, f.deploy.Public()) + "\n"))
	}))
	t.Cleanup(keys.Close)
	provider := privatekey.New()
	provider.KeysURL, provider.Client, provider.MetaURL = keys.URL+"/", keys.Client(), ""
	registry := detect.NewRegistry(provider)

	for _, workers := range []int{1, 3} {
		res, err := Repo(ctx, "fixture", repo, Remote{Contributors: []string{"octocat", "hubot"}}, Options{Workers: workers, Providers: registry})
		must(t, err)
		byKind := map[detect.Kind][]Finding{}
		for _, fd := range res.Findings {
			byKind[fd.Kind] = append(byKind[fd.Kind], fd)
		}
		if len(res.Findings) != 5 || len(byKind[privatekey.KindSSH]) != 3 || len(byKind[privatekey.KindTLS]) != 1 || len(byKind[privatekey.KindCosign]) != 1 {
			t.Fatalf("workers=%d: %+v", workers, res.Findings)
		}
		// Usable keys come before the encrypted ones, whatever their kind:
		// the cosign key and the passphrase-protected backup come last.
		for i, fd := range res.Findings {
			if fd.Encrypted != (i >= 3) {
				t.Fatalf("workers=%d: finding %d encrypted=%v: %+v", workers, i, fd.Encrypted, res.Findings)
			}
		}

		deploy := findByToken(t, res.Findings, f.deployFP)
		if deploy.Kind != privatekey.KindSSH || deploy.Redacted != f.deployFP || deploy.Attribution != "ed25519, unencrypted, comment deploy@ci; matches octocat's GitHub SSH key" {
			t.Fatalf("deploy key: %+v", deploy)
		}
		want := []Unlock{
			{Repo: "fixture", Path: "authorized_keys", Detail: "ssh public key, comment deploy@ci"},
			{Repo: "fixture", Path: "deploy/id_ed25519.pub", Detail: "ssh public key, comment deploy@ci"},
			{Repo: "fixture", Path: "infra.tf", Detail: "ssh public key"},
		}
		if !reflect.DeepEqual(deploy.Unlocks, want) {
			t.Fatalf("deploy unlocks: %+v", deploy.Unlocks)
		}

		// The SEC1 key under id_ecdsa is an SSH key by its path alone.
		legacy := findByToken(t, res.Findings, spkiOf(t, f.legacy.Public()))
		if legacy.Kind != privatekey.KindSSH || legacy.Unlocks != nil || legacy.Attribution != "ECDSA P-256, unencrypted" {
			t.Fatalf("legacy key: %+v", legacy)
		}

		tlsKey := findByToken(t, res.Findings, f.tlsSPKI)
		if tlsKey.Kind != privatekey.KindTLS || len(tlsKey.Unlocks) != 1 || tlsKey.Unlocks[0].Path != "tls/server.crt" || !strings.HasPrefix(tlsKey.Unlocks[0].Detail, "certificate for www.example.com, expires ") || !strings.HasSuffix(tlsKey.Unlocks[0].Detail, ", self-signed") {
			t.Fatalf("tls key: %+v", tlsKey)
		}

		cosign := byKind[privatekey.KindCosign][0]
		wantCosign := []Unlock{
			{Repo: "fixture", Path: "policies/verify.yaml", Detail: "public key (ECDSA P-256), pinned by Kyverno ClusterPolicy verify-images"},
			{Repo: "fixture", Path: "signing/cosign.pub", Detail: "public key (ECDSA P-256)"},
		}
		if !reflect.DeepEqual(cosign.Unlocks, wantCosign) || !cosign.Encrypted || cosign.Locations[0].Path != "signing/cosign.key" {
			t.Fatalf("cosign: %+v", cosign)
		}

		out, err := json.Marshal(res)
		must(t, err)
		for name, material := range map[string]string{"deploy": opensshPEM(t, f.deploy, "deploy@ci", ""), "tls": pkcs8PEM(t, f.tls)} {
			body := strings.Split(material, "\n")[1]
			if strings.Contains(string(out), body) {
				t.Fatalf("%s key material in the JSON", name)
			}
		}
		if !strings.Contains(string(out), `"detail":"public key (ECDSA P-256), pinned by Kyverno ClusterPolicy verify-images"`) || !strings.Contains(string(out), `"encrypted":true`) {
			t.Fatalf("json: %s", out)
		}
	}
}

func TestRepoIgnoresReclassifiedKinds(t *testing.T) {
	ctx := context.Background()
	f := newPrivateKeyFixture(t)
	repo, err := gitrepo.Open(ctx, f.dir)
	must(t, err)
	provider := privatekey.New()
	provider.KeysURL, provider.MetaURL = "", ""
	res, err := Repo(ctx, "fixture", repo, Remote{}, Options{Workers: 1, Providers: detect.NewRegistry(provider), Ignore: map[string]bool{string(privatekey.KindSSH): true}})
	must(t, err)
	for _, fd := range res.Findings {
		if fd.Kind == privatekey.KindSSH {
			t.Fatalf("an SSH key reclassified after Find must still honour --ignore: %+v", fd)
		}
	}
	if len(res.Findings) != 2 {
		t.Fatalf("want the TLS and cosign keys only, got %+v", res.Findings)
	}
}

func TestNoreplyLoginsAndCommitters(t *testing.T) {
	commit := "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Octo Cat <12345+octocat@users.noreply.github.com> 1700000000 +0000\ncommitter Hu Bot <hubot@users.noreply.github.com> 1700000000 +0000\n\nauthor Someone <mention@users.noreply.github.com> in the message\n"
	if got := noreplyLogins([]byte(commit)); !reflect.DeepEqual(got, []string{"octocat", "hubot"}) {
		t.Fatalf("logins %v", got)
	}
	if got := noreplyLogins([]byte("tree x\nauthor Jane <jane@example.com> 1 +0000\n\nmsg\n")); got != nil {
		t.Fatalf("no noreply address, got %v", got)
	}
	got := committers(map[string]bool{"octocat": true, "abe": true}, []string{"octocat", "zed", "", "abe", "yan"})
	if !reflect.DeepEqual(got, []string{"abe", "octocat", "zed", "yan"}) {
		t.Fatalf("committers %v", got)
	}
	many := map[string]bool{}
	for i := range maxLogins + 10 {
		many[strings.Repeat("a", 1+i%5)+string(rune('a'+i%26))+strings.Repeat("z", i/26)] = true
	}
	if got := committers(many, nil); len(got) != maxLogins {
		t.Fatalf("%d logins, want the cap %d", len(got), maxLogins)
	}
}

func findByToken(t *testing.T, findings []Finding, token string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Token == token {
			return f
		}
	}
	t.Fatalf("no finding named %s in %+v", token, findings)
	return Finding{}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func genEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	return key
}

func genECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	return key
}

func opensshPEM(t *testing.T, key ed25519.PrivateKey, comment, passphrase string) string {
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
	must(t, err)
	return string(pem.EncodeToMemory(block))
}

func pkcs8PEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	must(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func sec1PEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	must(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func pkixPEM(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	must(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func spkiOf(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	must(t, err)
	sum := sha256Sum(der)
	return sum
}

func certPEM(t *testing.T, key *ecdsa.PrivateKey, cn string) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	must(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func cosignPEM(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"kdf": map[string]string{"name": "scrypt"}, "cipher": map[string]string{"name": "nacl/secretbox"}, "ciphertext": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 48)))})
	must(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: raw}))
}

func authorized(t *testing.T, pub any) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	must(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func sshFingerprint(t *testing.T, pub any) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	must(t, err)
	return ssh.FingerprintSHA256(sshPub)
}

func indent(block string, n int) string {
	var b strings.Builder
	for line := range strings.Lines(block) {
		b.WriteString(strings.Repeat(" ", n) + line)
	}
	return strings.TrimRight(b.String(), "\n")
}

func sha256Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
