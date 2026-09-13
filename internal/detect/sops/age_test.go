package sops

import (
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/teemow/patty/internal/detect"
)

var find = New().Find

// identity generates an age identity at runtime, so no identity is ever
// committed to this repository.
func identity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// corrupt replaces the last character of an identity with another one of
// the alphabet, which breaks the Bech32 checksum.
func corrupt(s string) string {
	last := s[len(s)-1]
	for _, c := range bech32Upper {
		if byte(c) != last {
			return s[:len(s)-1] + string(c)
		}
	}
	panic("unreachable")
}

func TestFindAgeIdentity(t *testing.T) {
	id := identity(t)
	secret := id.String()
	if len(secret) != ageLen || !strings.HasPrefix(secret, agePrefix) {
		t.Fatalf("age changed its identity format: %d characters", len(secret))
	}
	content := []byte("# created: 2026-01-01T00:00:00Z\n# public key: " + id.Recipient().String() + "\n" + secret + "\n")
	got := find(content)
	if len(got) != 1 {
		t.Fatalf("want 1 token, got %d", len(got))
	}
	tok := got[0]
	if tok.Kind != KindAge || tok.Value != secret || !tok.ChecksumVerified || tok.Secret != "" {
		t.Fatalf("unexpected token %+v", tok)
	}
	if tok.Offset != strings.Index(string(content), secret) {
		t.Fatalf("wrong offset %d", tok.Offset)
	}
	if tok.Attribution != "recipient "+id.Recipient().String() {
		t.Fatalf("attribution must be the public key, got %q", tok.Attribution)
	}
	if got := detect.Redact(secret); strings.Contains(got, secret[10:60]) || !strings.HasPrefix(got, "AGE-SECR") {
		t.Fatalf("redaction %q", got)
	}
}

func TestFindAgeRejectsBadChecksum(t *testing.T) {
	secret := identity(t).String()
	if got := find([]byte("SOPS_AGE_KEY=" + corrupt(secret) + "\n")); len(got) != 0 {
		t.Fatalf("identity with a wrong checksum must not be reported, got %+v", got)
	}
}

func TestFindAgeRejectsWrongShape(t *testing.T) {
	secret := identity(t).String()
	cases := map[string]string{
		"truncated":       secret[:len(secret)-1],
		"trailing alnum":  secret + "Q",
		"leading alnum":   "X" + secret,
		"lower case":      strings.ToLower(secret),
		"non-bech32 body": secret[:20] + "B" + secret[21:], // B is not in the alphabet
		"prefix only":     agePrefix,
		"recipient only":  identity(t).Recipient().String(),
		"empty":           "",
	}
	for name, c := range cases {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindSeveralIdentities(t *testing.T) {
	a, b := identity(t), identity(t)
	got := find([]byte(a.String() + "\n" + b.String() + "\n" + a.String()))
	if len(got) != 3 || got[0].Value != a.String() || got[1].Value != b.String() || got[2].Value != a.String() {
		t.Fatalf("want three identities in order, got %+v", got)
	}
}

func TestRecipient(t *testing.T) {
	id := identity(t)
	if r, ok := Recipient(id.String()); !ok || r != id.Recipient().String() {
		t.Fatalf("Recipient = %q, %v", r, ok)
	}
	if _, ok := Recipient(corrupt(id.String())); ok {
		t.Fatal("corrupted identity must not yield a recipient")
	}
}
