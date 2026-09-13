package sops

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// pgpKey generates an ed25519 key with a Curve25519 encryption subkey at
// runtime and returns it armored, protected with passphrase when one is
// given. No key material is committed to this repository.
func pgpKey(t *testing.T, name, email, passphrase string) (string, *openpgp.Entity) {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", email, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519})
	if err != nil {
		t.Fatal(err)
	}
	if passphrase != "" {
		if err := e.EncryptPrivateKeys([]byte(passphrase), nil); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), e
}

func TestFindPGPPrivateKey(t *testing.T) {
	armored, e := pgpKey(t, "Selma Bouvier", "selma@dmv.springfield", "")
	if !strings.HasPrefix(armored, string(pgpBegin)) || !strings.Contains(armored, string(pgpEnd)) {
		t.Fatalf("go-crypto changed the armor markers:\n%s", armored)
	}
	content := []byte("apiVersion: v1\nkind: Secret\nstringData:\n  key: |\n" + armored + "\n")
	got := find(content)
	if len(got) != 1 {
		t.Fatalf("want 1 token, got %d", len(got))
	}
	tok := got[0]
	fp := Fingerprint(e.PrimaryKey)
	if tok.Kind != KindPGP || tok.Value != fp || len(fp) != fingerprintLen || !tok.ChecksumVerified || tok.Secret != "" {
		t.Fatalf("unexpected token %+v", tok)
	}
	if tok.Offset != strings.Index(string(content), string(pgpBegin)) {
		t.Fatalf("offset must be the armor header, got %d", tok.Offset)
	}
	if tok.Attribution != "fingerprint "+fp+", Selma Bouvier <selma@dmv.springfield>, not passphrase-protected" {
		t.Fatalf("attribution %q", tok.Attribution)
	}
}

func TestFindPGPReportsPassphraseProtection(t *testing.T) {
	armored, e := pgpKey(t, "Patty Bouvier", "patty@dmv.springfield", "hunter2")
	got := find([]byte(armored))
	if len(got) != 1 || got[0].Value != Fingerprint(e.PrimaryKey) {
		t.Fatalf("got %+v", got)
	}
	if !strings.HasSuffix(got[0].Attribution, ", passphrase-protected") {
		t.Fatalf("attribution %q", got[0].Attribution)
	}
}

func TestFindPGPSeveralKeysInOneBlock(t *testing.T) {
	_, a := pgpKey(t, "A", "a@dmv.springfield", "")
	_, b := pgpKey(t, "B", "b@dmv.springfield", "pw")
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*openpgp.Entity{a, b} {
		if err := e.SerializePrivateWithoutSigning(w, nil); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	got := find(buf.Bytes())
	if len(got) != 2 || got[0].Value != Fingerprint(a.PrimaryKey) || got[1].Value != Fingerprint(b.PrimaryKey) || got[0].Offset != got[1].Offset {
		t.Fatalf("want both keys of the ring at the block's offset, got %+v", got)
	}
}

func TestFindPGPRejectsGarbage(t *testing.T) {
	armored, _ := pgpKey(t, "C", "c@dmv.springfield", "")
	lines := strings.Split(armored, "\n")
	// Damage the body: every base64 line becomes the same line, which does
	// not decode to key packets.
	for i := 2; i < len(lines)-2; i++ {
		lines[i] = strings.Repeat("A", len(lines[i]))
	}
	cases := map[string]string{
		"header only":     string(pgpBegin) + "\n\nAAAA\n",
		"no end marker":   strings.Join(lines[:len(lines)/2], "\n"),
		"damaged body":    strings.Join(lines, "\n"),
		"public key type": strings.ReplaceAll(armored, "PRIVATE", "PUBLIC"),
	}
	for name, c := range cases {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}
