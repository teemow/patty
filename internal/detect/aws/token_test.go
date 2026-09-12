package aws

import (
	"encoding/base32"
	"fmt"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// Every test key is assembled at runtime so no key-shaped literal is
// committed. The two bodies are the ones AWS and the public write-up of the
// account id encoding use as examples.
var (
	docBody  = "IOSFODNN7EXAMPLE"
	demoBody = "Y34FZKBOKMUTVV7A"
	// mixed is forty base64 characters of mixed case, the shape of a secret.
	mixed = strings.Repeat("Ab1+", 10)
	// long is a session token: hundreds of base64 characters with padding.
	long = strings.Repeat("Ses5ion+", 40) + "=="
)

func akia() string { return "AKIA" + docBody }
func asia() string { return "ASIA" + demoBody }

var find = New().Find

func TestAccount(t *testing.T) {
	// Checked against an independent implementation of the published
	// algorithm; the second value is the one the write-up gives.
	if got := Account(akia()); got != "581039954779" {
		t.Errorf("Account(AKIA…) = %q", got)
	}
	if got := Account(asia()); got != "609629065308" {
		t.Errorf("Account(ASIA…) = %q", got)
	}
	// Round trip through the encoding: the account id sits in the top 48
	// bits, shifted left by seven, and small ids are zero-padded.
	for _, account := range []uint64{1, 42, 123456789012, 999999999999} {
		if got := Account(keyFor(account)); got != fmt.Sprintf("%012d", account) {
			t.Errorf("Account(keyFor(%d)) = %q", account, got)
		}
	}
	if Account("AKIA"+strings.Repeat("0", 16)) != "" {
		t.Error("a body outside the base32 alphabet has no account")
	}
}

// keyFor builds a key id that decodes to the given account id.
func keyFor(account uint64) string {
	var raw [10]byte
	v := account << accountShift
	for i := 5; i >= 0; i-- {
		raw[i] = byte(v)
		v >>= 8
	}
	return "AKIA" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
}

func TestFindEveryPrefix(t *testing.T) {
	cases := []struct {
		name, value string
		kind        detect.Kind
	}{
		{"AKIA", akia(), KindAccessKey},
		{"ASIA", asia(), KindTemporaryKey},
		{"ABIA", "ABIA" + docBody, KindAccessKey},
		{"ACCA", "ACCA" + docBody, KindAccessKey},
		{"A3T", "A3T" + "7" + docBody, KindAccessKey},
	}
	for _, c := range cases {
		for _, wrap := range []string{"%s", "aws_access_key_id = %s\n", "\"%s\"", "AWS_ACCESS_KEY_ID=%s;", "--access-key-id %s --status Inactive", "(%s)"} {
			content := strings.Replace(wrap, "%s", c.value, 1)
			got := find([]byte(content))
			if len(got) != 1 {
				t.Errorf("%s in %q: want 1 token, got %+v", c.name, wrap, got)
				continue
			}
			want := "account " + Account(c.value) + ", key id only, secret not found nearby"
			if got[0].Kind != c.kind || got[0].Value != c.value || got[0].Attribution != want || got[0].Secret != "" || got[0].ChecksumVerified {
				t.Errorf("%s: unexpected %+v", c.name, got[0])
			}
			if got[0].Offset != strings.Index(content, c.value) {
				t.Errorf("%s: wrong offset %d", c.name, got[0].Offset)
			}
		}
	}
}

func TestFindRejectsWrongShapes(t *testing.T) {
	cases := map[string]string{
		"letter before":      "X" + akia(),
		"digit before":       "1" + akia(),
		"letter after":       akia() + "Q",
		"digit after":        akia() + "2",
		"too short":          akia()[:19],
		"zero in body":       "AKIA" + "I0SFODNN7EXAMPLE",
		"one in body":        "AKIA" + "I1SFODNN7EXAMPLE",
		"eight in body":      "AKIA" + "I8SFODNN7EXAMPLE",
		"nine in body":       "AKIA" + "I9SFODNN7EXAMPLE",
		"lowercase in body":  "AKIA" + "iOSFODNN7EXAMPLE",
		"A3T then lowercase": "A3T" + "x" + docBody,
		"A3T then symbol":    "A3T" + "-" + docBody,
		"other prefix":       "AXIA" + docBody,
		"inside a word":      "MAKIA" + docBody + "S",
		"empty":              "",
	}
	for name, content := range cases {
		if got := find([]byte(content)); got != nil {
			t.Errorf("%s: %q must not match, got %+v", name, content, got)
		}
	}
}

func TestFindPairsSecrets(t *testing.T) {
	sha1 := strings.Repeat("0123456789abcdef", 2) + "01234567"
	acct := "account " + Account(akia())
	cases := []struct {
		name, content string
		secret        string
		attribution   string
	}{
		{"credentials file", "[default]\naws_access_key_id = " + akia() + "\naws_secret_access_key = " + mixed + "\nregion = eu-west-1\n", mixed, acct + ", key pair"},
		{"env file", "AWS_ACCESS_KEY_ID=" + akia() + "\nAWS_SECRET_ACCESS_KEY=" + mixed + "\n", mixed, acct + ", key pair"},
		{"json one-liner", `{"AccessKeyId":"` + akia() + `","SecretAccessKey":"` + mixed + `"}`, mixed, acct + ", key pair"},
		{"terraform", `provider "aws" {` + "\n  secret_key = \"" + mixed + "\"\n  access_key = \"" + akia() + "\"\n}\n", mixed, acct + ", key pair"},
		{"next line, no keyword", akia() + "\n" + mixed + "\n", mixed, acct + ", key pair"},
		{"same line, no keyword", akia() + ":" + mixed, mixed, acct + ", key pair"},
		{"far away, no keyword", akia() + "\n" + strings.Repeat("x\n", 50) + mixed, mixed, acct + ", key pair"},
		{"id only", "key " + akia() + " has no secret here", "", acct + ", key id only, secret not found nearby"},
		{"git object id is not a secret", akia() + "\n" + sha1 + "\n", "", acct + ", key id only, secret not found nearby"},
		{"39 characters", akia() + "\n" + mixed[:39] + "\n", "", acct + ", key id only, secret not found nearby"},
		{"41 characters", akia() + "\n" + mixed + "Z\n", "", acct + ", key id only, secret not found nearby"},
		{"all lowercase", akia() + "\n" + strings.ToLower(mixed) + "\n", "", acct + ", key id only, secret not found nearby"},
		{"keyword beats a closer candidate", akia() + "\n" + strings.Repeat("Zz9/", 10) + "\nsecret_key: " + mixed + "\n", mixed, acct + ", key pair"},
		{"after beats before at equal distance", strings.Repeat("Zz9/", 10) + "\n" + akia() + "\n" + mixed + "\n", mixed, acct + ", key pair"},
		{"secret quoted inside base64 padding", "aws_secret_access_key=" + mixed + "=\n" + akia(), mixed, acct + ", key pair"},
	}
	for _, c := range cases {
		got := find([]byte(c.content))
		if len(got) != 1 {
			t.Errorf("%s: want 1 token, got %+v", c.name, got)
			continue
		}
		if got[0].Secret != c.secret || got[0].Attribution != c.attribution {
			t.Errorf("%s: secret %q attribution %q, want %q %q", c.name, got[0].Secret, got[0].Attribution, c.secret, c.attribution)
		}
	}
}

func TestFindPairsEachProfile(t *testing.T) {
	other := strings.Repeat("Zz9/", 10)
	second := keyFor(42)
	content := "[dev]\naws_access_key_id = " + akia() + "\naws_secret_access_key = " + mixed + "\n\n[prod]\naws_access_key_id = " + second + "\naws_secret_access_key = " + other + "\n"
	got := find([]byte(content))
	if len(got) != 2 || got[0].Secret != mixed || got[1].Secret != other {
		t.Fatalf("each key gets its own secret: %+v", got)
	}
	if got[1].Attribution != "account 000000000042, key pair" {
		t.Errorf("attribution: %q", got[1].Attribution)
	}
}

func TestFindPairsSessionTokens(t *testing.T) {
	acct := "account " + Account(asia())
	cases := []struct {
		name, content string
		secret        string
		attribution   string
	}{
		{"full set", "export AWS_ACCESS_KEY_ID=" + asia() + "\nexport AWS_SECRET_ACCESS_KEY=" + mixed + "\nexport AWS_SESSION_TOKEN=" + long + "\n", mixed + "\n" + long, acct + ", key pair with session token"},
		{"json", `{"AccessKeyId":"` + asia() + `","SecretAccessKey":"` + mixed + `","SessionToken":"` + long + `"}`, mixed + "\n" + long, acct + ", key pair with session token"},
		{"no session token", "AWS_ACCESS_KEY_ID=" + asia() + "\nAWS_SECRET_ACCESS_KEY=" + mixed + "\n", mixed, acct + ", key pair, session token not found nearby"},
		{"id only", asia(), "", acct + ", key id only, secret not found nearby"},
	}
	for _, c := range cases {
		got := find([]byte(c.content))
		if len(got) != 1 || got[0].Kind != KindTemporaryKey {
			t.Errorf("%s: want 1 temporary key, got %+v", c.name, got)
			continue
		}
		if got[0].Secret != c.secret || got[0].Attribution != c.attribution {
			t.Errorf("%s: secret %q attribution %q, want %q %q", c.name, got[0].Secret, got[0].Attribution, c.secret, c.attribution)
		}
		secret, session := credentials(got[0])
		if want, _, _ := strings.Cut(c.secret, "\n"); secret != want || (session != "") != strings.Contains(c.secret, "\n") {
			t.Errorf("%s: credentials() = %q, %q", c.name, secret, session)
		}
	}
	// A long-lived key never takes a session token.
	got := find([]byte(akia() + "\n" + mixed + "\n" + long + "\n"))
	if len(got) != 1 || got[0].Secret != mixed || got[0].Attribution != "account "+Account(akia())+", key pair" {
		t.Errorf("AKIA with a session token nearby: %+v", got)
	}
}

func TestFingerprintAndRedactionUseTheKeyIDOnly(t *testing.T) {
	got := find([]byte(akia() + "\n" + mixed + "\n"))
	if len(got) != 1 || got[0].Fingerprint() != detect.Fingerprint(akia()) {
		t.Fatalf("fingerprint is the key id's: %+v", got)
	}
	if r := detect.Redact(got[0].Value); strings.Contains(r, mixed) || !strings.HasPrefix(r, "AKIA") {
		t.Errorf("redacted %q", r)
	}
}

func TestKindsAndLocalSources(t *testing.T) {
	p := New()
	var _ detect.Provider = p
	if _, ok := detect.Provider(p).(detect.DryRunRevoker); ok {
		t.Fatal("IAM has no dry run")
	}
	kinds := p.Kinds()
	if len(kinds) != 2 || kinds[0].Kind != KindAccessKey || !kinds[0].Revocable || kinds[1].Kind != KindTemporaryKey || kinds[1].Revocable {
		t.Fatalf("kinds: %+v", kinds)
	}
	for _, k := range kinds {
		if k.RevokePage == "" || k.RevokeNote == "" || !strings.Contains(k.AuditNote, "CloudTrail") || !strings.Contains(k.AuditNote, "AWSCompromisedKeyQuarantine") {
			t.Errorf("%s: incomplete advice %+v", k.Kind, k)
		}
	}
	if !strings.Contains(kinds[0].RevokeNote, "aws iam update-access-key") || !strings.Contains(kinds[0].RevokeNote, "aws iam delete-access-key") {
		t.Errorf("manual advice: %q", kinds[0].RevokeNote)
	}
	src := p.LocalSources()
	if len(src.Env) != 3 || src.Env[0] != "AWS_ACCESS_KEY_ID" || len(src.HomeFiles) != 4 || src.HomeFiles[0] != ".aws/credentials" || len(src.ConfigFiles) != 1 || len(src.Commands) != 0 {
		t.Fatalf("local sources: %+v", src)
	}
}
