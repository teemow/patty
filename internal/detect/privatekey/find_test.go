package privatekey

import (
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func one(t *testing.T, content string) detect.Token {
	t.Helper()
	found := New().Find([]byte(content))
	if len(found) != 1 {
		t.Fatalf("want one finding, got %+v", found)
	}
	return found[0]
}

func TestFindOpenSSHKeys(t *testing.T) {
	ed, ec, rsaK := ed25519Key(t), ecdsaKey(t), rsaKey(t)
	cases := []struct {
		name, pem, attribution, value string
	}{
		{"ed25519", openssh(t, ed, "jane@example.com", ""), "ed25519, unencrypted, comment jane@example.com", fingerprint(t, ed.Public())},
		{"ecdsa", openssh(t, ec, "", ""), "ECDSA P-256, unencrypted", fingerprint(t, ec.Public())},
		{"rsa", openssh(t, rsaK, "deploy key", ""), "RSA 2048, unencrypted, comment deploy key", fingerprint(t, rsaK.Public())},
	}
	for _, c := range cases {
		tok := one(t, "# a key\n"+c.pem)
		if tok.Kind != KindSSH || tok.Value != c.value || tok.Attribution != c.attribution || tok.Encrypted || tok.Offset != len("# a key\n") {
			t.Errorf("%s: %+v", c.name, tok)
		}
		if tok.Secret != c.pem {
			t.Errorf("%s: the block must travel in Secret for verification", c.name)
		}
	}
}

func TestFindEncryptedOpenSSHKeyKeepsPublicKey(t *testing.T) {
	ed := ed25519Key(t)
	tok := one(t, openssh(t, ed, "jane@example.com", "hunter2"))
	if tok.Kind != KindSSH || tok.Value != fingerprint(t, ed.Public()) || !tok.Encrypted || tok.Secret != "" || tok.Attribution != "ed25519, encrypted" {
		t.Fatalf("%+v", tok)
	}
}

func TestFindPEMKeys(t *testing.T) {
	ec, rsaK := ecdsaKey(t), rsaKey(t)
	cases := []struct {
		name, pem, attribution, value string
		kind                          detect.Kind
		encrypted                     bool
	}{
		{"pkcs8 ec", pkcs8(t, ec), "ECDSA P-256, unencrypted", spki(t, ec.Public()), KindTLS, false},
		{"pkcs8 rsa", pkcs8(t, rsaK), "RSA 2048, unencrypted", spki(t, rsaK.Public()), KindTLS, false},
		{"pkcs1", pkcs1(rsaK), "RSA 2048, unencrypted", spki(t, rsaK.Public()), KindTLS, false},
		{"sec1", sec1(t, ec), "ECDSA P-256, unencrypted", spki(t, ec.Public()), KindTLS, false},
		{"legacy encrypted", legacyEncrypted(t, rsaK), "RSA, encrypted", "", KindTLS, true},
		{"pkcs8 encrypted", pkcs8Encrypted(t), "PKCS#8, encrypted, algorithm unknown", "", KindTLS, true},
		{"cosign", cosignKey(t), "encrypted with scrypt/nacl/secretbox, public key not derivable", "", KindCosign, true},
	}
	for _, c := range cases {
		tok := one(t, c.pem)
		if tok.Kind != c.kind || tok.Attribution != c.attribution || tok.Encrypted != c.encrypted {
			t.Errorf("%s: %+v", c.name, tok)
		}
		switch {
		case c.value != "" && tok.Value != c.value:
			t.Errorf("%s: value %s, want %s", c.name, tok.Value, c.value)
		case c.value == "" && !strings.HasPrefix(tok.Value, "sha256:"):
			t.Errorf("%s: encrypted material is named by its block hash, got %s", c.name, tok.Value)
		}
		if (tok.Secret != "") == c.encrypted {
			t.Errorf("%s: secret kept = %v", c.name, tok.Secret != "")
		}
	}
	// A PKCS#8 key and a PKCS#1 key of the same RSA key are one credential.
	if one(t, pkcs8(t, rsaK)).Value != one(t, pkcs1(rsaK)).Value {
		t.Fatal("the same key in two containers must have one name")
	}
}

func TestFindEmbeddedForms(t *testing.T) {
	ec := ecdsaKey(t)
	plain := pkcs8(t, ec)
	want := one(t, plain)
	forms := map[string]string{
		"json":      `{"key": "` + escaped(plain) + `"}`,
		"terraform": "resource \"x\" \"y\" {\n  private_key = \"" + escaped(plain) + "\"\n}\n",
		"yaml":      "tls:\n  key: |\n" + indented(plain),
		"crlf":      strings.ReplaceAll(plain, "\n", "\r\n"),
		"quoted":    "KEY='" + plain + "'\n",
	}
	for name, content := range forms {
		got := one(t, content)
		if got.Value != want.Value || got.Secret != want.Secret || got.Kind != KindTLS {
			t.Errorf("%s: %+v", name, got)
		}
	}
	// An escaped encrypted block normalizes to the same hash as the plain one.
	enc := legacyEncrypted(t, rsaKey(t))
	if one(t, enc).Value != one(t, `{"k":"`+escaped(enc)+`"}`).Value {
		t.Fatal("block hash must not depend on the escaping")
	}
}

func TestFindLeavesServiceAccountKeysToGoogle(t *testing.T) {
	key := pkcs8(t, rsaKey(t))
	doc := `{"type": "service_account", "project_id": "example", "private_key_id": "abc", "private_key": "` + escaped(key) + `\n", "client_email": "svc@example.iam.gserviceaccount.com"}`
	if got := New().Find([]byte(doc)); got != nil {
		t.Fatalf("a service account key is Google Cloud's finding, got %+v", got)
	}
	// Escaped once more, as the password of a Docker config.
	nested := `{"auths": {"gcr.io": {"password": "` + strings.ReplaceAll(strings.ReplaceAll(doc, `\`, `\\`), `"`, `\"`) + `"}}}`
	if got := New().Find([]byte(nested)); got != nil {
		t.Fatalf("nested service account key, got %+v", got)
	}
	// The same field name in a document that is not a service account key is a key.
	if got := New().Find([]byte(`{"private_key": "` + escaped(key) + `"}`)); len(got) != 1 {
		t.Fatalf("a private_key field elsewhere is a finding, got %+v", got)
	}
}

func TestFindIgnoresOtherBlocks(t *testing.T) {
	ec := ecdsaKey(t)
	certPEM, _ := certificate(t, ec.Public(), "example.com", nil, farFuture, false, nil, ec)
	cases := map[string]string{
		"certificate":  certPEM,
		"public key":   publicPEM(t, ec.Public()),
		"pgp":          "-" + dashes + "BEGIN PGP PRIVATE KEY BLOCK" + dashes + "\nAAAA\n" + dashes + "END PGP PRIVATE KEY BLOCK" + dashes + "\n",
		"garbage":      dashes + "BEGIN " + labelPKCS8 + dashes + "\nnot base64!\n" + dashes + "END " + labelPKCS8 + dashes + "\n",
		"placeholder":  dashes + "BEGIN " + labelPKCS8 + dashes + "\n...\n" + dashes + "END " + labelPKCS8 + dashes + "\n",
		"no end":       dashes + "BEGIN " + labelPKCS8 + dashes + "\nAAAA\n",
		"joined word":  "x" + pkcs8(t, ec),
		"wrong cosign": string(cosignArmor(t, "not json")),
		"empty":        "",
	}
	for name, content := range cases {
		if got := New().Find([]byte(content)); got != nil {
			t.Errorf("%s: want nil, got %+v", name, got)
		}
	}
}

func TestFindSeveralBlocksAndLines(t *testing.T) {
	ed, ec := ed25519Key(t), ecdsaKey(t)
	content := "# keys\n" + openssh(t, ed, "", "") + "\n" + pkcs8(t, ec)
	found := detect.NewRegistry(New()).Find([]byte(content))
	if len(found) != 2 || found[0].Kind != KindSSH || found[0].Line != 2 || found[1].Kind != KindTLS {
		t.Fatalf("%+v", found)
	}
	if want := strings.Count("# keys\n"+openssh(t, ed, "", "")+"\n", "\n") + 1; found[1].Line != want {
		t.Fatalf("second block on line %d, want %d", found[1].Line, want)
	}
}

func TestOpenSSHComment(t *testing.T) {
	for _, comment := range []string{"", "jane@example.com", "a comment with spaces", "ünïcödé"} {
		for name, key := range map[string]any{"ed25519": ed25519Key(t), "ecdsa": ecdsaKey(t), "rsa": rsaKey(t)} {
			if got := opensshComment([]byte(openssh(t, key, comment, ""))); got != comment {
				t.Errorf("%s comment %q: got %q", name, comment, got)
			}
		}
	}
	if got := opensshComment([]byte(openssh(t, ed25519Key(t), "secret", "pw"))); got != "" {
		t.Fatalf("an encrypted key has no readable comment, got %q", got)
	}
	if got := opensshComment([]byte(pkcs8(t, ecdsaKey(t)))); got != "" {
		t.Fatalf("a PKCS#8 key has no comment, got %q", got)
	}
}
