package privatekey

import (
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/teemow/patty/internal/detect"
)

var farFuture = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

func cosignArmor(t *testing.T, body string) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: labelSigstore, Bytes: []byte(body)})
}

func TestObserveSSHPublicKeys(t *testing.T) {
	ed, rsaK := ed25519Key(t), rsaKey(t)
	edLine, rsaLine := authorizedLine(t, ed.Public(), "jane@laptop"), authorizedLine(t, rsaK.Public(), "")
	cases := map[string]struct {
		content string
		want    []detect.Sighting
	}{
		"authorized_keys": {
			"# keys\ncommand=\"/usr/bin/deploy\",no-pty " + edLine + "\n" + rsaLine + "\n",
			[]detect.Sighting{{ID: fingerprint(t, ed.Public()), Detail: "ssh public key, comment jane@laptop"}, {ID: fingerprint(t, rsaK.Public()), Detail: "ssh public key"}},
		},
		"terraform": {
			"resource \"github_repository_deploy_key\" \"ci\" {\n  key = \"" + edLine + "\"\n}\n",
			[]detect.Sighting{{ID: fingerprint(t, ed.Public()), Detail: "ssh public key, comment jane@laptop"}},
		},
		"yaml": {
			"ssh_authorized_keys:\n  - " + rsaLine + " ci@example.com\n",
			[]detect.Sighting{{ID: fingerprint(t, rsaK.Public()), Detail: "ssh public key, comment ci@example.com"}},
		},
		"corrupted":  {strings.Replace(edLine, "AAAAC3", "AAAAC4", 1) + "\n", nil},
		"prose":      {"run ssh-keygen -t ed25519 and paste the ssh-ed25519 line here\n", nil},
		"joined":     {"x" + edLine + "\n", nil},
		"no key":     {"ssh-rsa\n", nil},
		"escaped":    {`"` + edLine + `\n"`, []detect.Sighting{{ID: fingerprint(t, ed.Public()), Detail: "ssh public key, comment jane@laptop"}}},
		"wrong type": {"ssh-rsa " + strings.Fields(edLine)[1] + "\n", nil},
	}
	for name, c := range cases {
		if got := New().Observe([]byte(c.content)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", name, got, c.want)
		}
	}
}

func TestObserveCertificates(t *testing.T) {
	caKey, leafKey := ecdsaKey(t), ecdsaKey(t)
	caPEM, ca := certificate(t, caKey.Public(), "Example CA", nil, farFuture, true, nil, caKey)
	leafPEM, _ := certificate(t, leafKey.Public(), "www.example.com", []string{"www.example.com", "example.com", "a.example.com", "b.example.com"}, time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC), false, ca, caKey)
	expiredPEM, _ := certificate(t, leafKey.Public(), "old.example.com", nil, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), false, nil, leafKey)

	got := New().Observe([]byte(caPEM + leafPEM + expiredPEM))
	want := []detect.Sighting{
		{ID: spki(t, caKey.Public()), Detail: "CA certificate for Example CA, expires 2099-01-01, self-signed"},
		{ID: spki(t, leafKey.Public()), Detail: "certificate for www.example.com, example.com, a.example.com, +2 more, expires 2030-06-01, issuer Example CA"},
		{ID: spki(t, leafKey.Public()), Detail: "certificate for old.example.com, expired 2020-01-01, self-signed"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// The certificate names the private key: same identifier as the key's Value.
	if key := one(t, pkcs8(t, leafKey)); key.Value != want[1].ID {
		t.Fatalf("key %s, certificate %s", key.Value, want[1].ID)
	}
	// A certificate in a Kubernetes Secret is seen by the registry.
	secret := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: web-tls\n  namespace: web\ntype: kubernetes.io/tls\ndata:\n  tls.crt: " + base64.StdEncoding.EncodeToString([]byte(leafPEM)) + "\n  tls.key: " + base64.StdEncoding.EncodeToString([]byte(pkcs8(t, leafKey))) + "\n"
	registry := detect.NewRegistry(New())
	if seen := registry.Observe([]byte(secret)); !reflect.DeepEqual(seen, want[1:2]) {
		t.Fatalf("secret: %+v", seen)
	}
	if found := registry.Find([]byte(secret)); len(found) != 1 || found[0].Kind != KindTLS || found[0].Attribution != "in Secret web/web-tls, key tls.key (ECDSA P-256, unencrypted)" {
		t.Fatalf("secret key: %+v", found)
	}
}

func TestObservePublicKeysAndPolicies(t *testing.T) {
	key := ecdsaKey(t)
	pub := publicPEM(t, key.Public())
	id := spki(t, key.Public())
	kyverno := "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: verify-images\nspec:\n  rules:\n    - name: check\n      verifyImages:\n        - imageReferences: [\"ghcr.io/example/*\"]\n          attestors:\n            - entries:\n                - keys:\n                    publicKeys: |-\n" + strings.ReplaceAll(indented(pub), "    ", "                      ") + "\n"
	cip := "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: example-cip\nspec:\n  images:\n    - glob: \"ghcr.io/example/**\"\n  authorities:\n    - key:\n        data: |\n" + strings.ReplaceAll(indented(pub), "    ", "          ")
	cases := map[string]struct {
		content string
		want    []detect.Sighting
	}{
		"cosign.pub": {pub, []detect.Sighting{{ID: id, Detail: "public key (ECDSA P-256)"}}},
		"kyverno":    {kyverno, []detect.Sighting{{ID: id, Detail: "public key (ECDSA P-256), pinned by Kyverno ClusterPolicy verify-images"}}},
		"cip":        {cip, []detect.Sighting{{ID: id, Detail: "public key (ECDSA P-256), pinned by ClusterImagePolicy example-cip"}}},
		"rsa":        {publicPEM(t, rsaKey(t).Public()), nil},
	}
	for name, c := range cases {
		got := New().Observe([]byte(c.content))
		if name == "rsa" {
			if len(got) != 1 || got[0].Detail != "public key (RSA 2048)" {
				t.Errorf("rsa: %+v", got)
			}
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", name, got, c.want)
		}
	}
	// The OpenSSH form of the same key, in a .pub written by ssh-keygen,
	// names a PEM key too: both forms are looked up, the PEM key by SPKI.
	if pemKey, sshPub := one(t, pkcs8(t, key)), New().Observe([]byte(authorizedLine(t, key.Public(), ""))); len(sshPub) != 1 || sshPub[0].ID == pemKey.Value {
		t.Fatalf("an authorized_keys line is known by its OpenSSH fingerprint: %+v vs %s", sshPub, pemKey.Value)
	}
}

func TestIdentifiersAdjacentAndClassify(t *testing.T) {
	p := New()
	if got := p.Identifiers(detect.Token{Kind: KindSSH, Value: "SHA256:abc"}); !reflect.DeepEqual(got, []string{"SHA256:abc"}) {
		t.Fatalf("identifiers %v", got)
	}
	if got := p.Identifiers(detect.Token{Kind: "github-pat", Value: "x"}); got != nil {
		t.Fatalf("foreign kind %v", got)
	}
	pubSighting := detect.Sighting{ID: "abcd", Detail: "public key (ECDSA P-256)"}
	if got := p.Adjacent(KindCosign, pubSighting); !reflect.DeepEqual(got, []string{"abcd"}) {
		t.Fatalf("adjacent %v", got)
	}
	if p.Adjacent(KindCosign, detect.Sighting{ID: "SHA256:x", Detail: "ssh public key"}) != nil || p.Adjacent(KindTLS, pubSighting) != nil {
		t.Fatal("only a cosign key adopts a PEM public key next to it")
	}
	tls := detect.Token{Kind: KindTLS, Value: "abcd"}
	cases := []struct {
		name    string
		tok     detect.Token
		paths   []string
		matched []string
		want    detect.Kind
	}{
		{"ssh match", tls, []string{"server.key"}, []string{"abcd", "SHA256:abc"}, KindSSH},
		{"id_ path", tls, []string{"keys/id_rsa"}, nil, KindSSH},
		{"ssh dir", tls, []string{".ssh/deploy"}, nil, KindSSH},
		{"pub path", tls, []string{"id_rsa.pub"}, nil, ""},
		{"tls path", tls, []string{"tls/server.key"}, []string{"abcd"}, ""},
		{"encrypted", detect.Token{Kind: KindTLS, Value: "sha256:ff"}, []string{"id_rsa"}, nil, ""},
		{"already ssh", detect.Token{Kind: KindSSH, Value: "SHA256:x"}, []string{"server.key"}, nil, ""},
	}
	for _, c := range cases {
		if got := p.Classify(c.tok, c.paths, c.matched); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
