package openai

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

const (
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alnum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// body returns n random characters of the given alphabet. Every key in
// these tests is built at run time, so no key-shaped string is committed.
func body(n int, alphabet string) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	for i, c := range raw {
		raw[i] = alphabet[int(c)%len(alphabet)]
	}
	return string(raw)
}

func key(prefix string, left, right int) string {
	return prefix + body(left, alphabet) + Marker + body(right, alphabet)
}

func newProjectKey() string        { return key("sk-proj-", 74, 74) }
func newServiceAccountKey() string { return key("sk-svcacct-", 58, 58) }
func newAdminKey() string          { return key("sk-admin-", 74, 58) }
func newLegacyKey() string         { return "sk-" + body(20, alnum) + Marker + body(20, alnum) }

func find(content string) []detect.Token {
	return detect.NewRegistry(New()).Find([]byte(content))
}

func TestFindEveryFamily(t *testing.T) {
	keys := map[detect.Kind]string{KindProject: newProjectKey(), KindServiceAccount: newServiceAccountKey(), KindAdmin: newAdminKey(), KindLegacy: newLegacyKey()}
	content := "OPENAI_API_KEY=" + keys[KindProject] + "\n" +
		`{"OPENAI_API_KEY":"` + keys[KindServiceAccount] + `"}` + "\n" +
		"export OPENAI_ADMIN_KEY='" + keys[KindAdmin] + "'\n" +
		"old: " + keys[KindLegacy] + "\n"
	found := find(content)
	if len(found) != 4 {
		t.Fatalf("want 4 tokens, got %d: %+v", len(found), found)
	}
	for i, tok := range found {
		if keys[tok.Kind] != tok.Value {
			t.Errorf("%s: got %q", tok.Kind, tok.Value)
		}
		if tok.ChecksumVerified {
			t.Errorf("%s: no OpenAI key carries a checksum", tok.Kind)
		}
		if content[tok.Offset:tok.Offset+len(tok.Value)] != tok.Value {
			t.Errorf("%s: offset %d does not point at the token", tok.Kind, tok.Offset)
		}
		if tok.Line != i+1 {
			t.Errorf("%s: line %d, want %d", tok.Kind, tok.Line, i+1)
		}
	}
	if len(newProjectKey()) != 164 || len(newLegacyKey()) != 51 {
		t.Errorf("key lengths %d and %d", len(newProjectKey()), len(newLegacyKey()))
	}
}

func TestFindAcceptsBothBodyLengths(t *testing.T) {
	for _, lens := range [][2]int{{74, 74}, {58, 58}, {74, 58}, {58, 74}} {
		k := key("sk-proj-", lens[0], lens[1])
		found := find("token: " + k + "\n")
		if len(found) != 1 || found[0].Value != k || found[0].Kind != KindProject {
			t.Errorf("%v: got %+v", lens, found)
		}
	}
}

func TestFindRejectsNearMisses(t *testing.T) {
	cases := map[string]string{
		"left body off by one":     key("sk-proj-", 73, 74),
		"right body off by one":    key("sk-proj-", 74, 75),
		"undocumented length":      key("sk-proj-", 60, 60),
		"no marker":                "sk-proj-" + body(156, alphabet),
		"marker in the wrong spot": "sk-proj-" + body(70, alphabet) + Marker + body(78, alphabet),
		"marker twice":             "sk-proj-" + body(74, alphabet) + Marker + body(74, alphabet) + Marker,
		"unknown prefix":           key("sk-team-", 74, 74),
		"continues into word":      newProjectKey() + "x",
		"continues with dash":      newProjectKey() + "-x",
		"preceded by word":         "x" + newProjectKey(),
		"preceded by underscore":   "_" + newProjectKey(),
		"legacy body off by one":   "sk-" + body(19, alnum) + Marker + body(20, alnum),
		"legacy with dash in body": "sk-" + body(19, alnum) + "-" + Marker + body(20, alnum),
		"legacy continues":         newLegacyKey() + "1",
		"marker alone":             "the marker " + Marker + " means OpenAI",
	}
	for name, content := range cases {
		if found := find(content); len(found) != 0 {
			t.Errorf("%s: matched %+v", name, found)
		}
	}
}

func TestFindAcceptsBoundaries(t *testing.T) {
	for name, content := range map[string]string{
		"quoted": `"` + newProjectKey() + `"`, "end of text": newAdminKey(), "before dot": newServiceAccountKey() + ".", "after equals": "key=" + newLegacyKey(),
		"after dash": "key-" + newProjectKey(),
	} {
		if found := find(content); len(found) != 1 {
			t.Errorf("%s: got %+v", name, found)
		}
	}
}

func TestKindsFollowConfiguration(t *testing.T) {
	p := New()
	p.Configure(func(string) string { return "" })
	for _, k := range p.Kinds() {
		if k.Revocable {
			t.Errorf("%s revocable without an admin key", k.Kind)
		}
	}
	registry := detect.NewRegistry(p)
	if !strings.Contains(registry.Info(KindProject).RevokeNote, AdminKeyEnv) {
		t.Errorf("advice does not name %s: %q", AdminKeyEnv, registry.Info(KindProject).RevokeNote)
	}
	p.Configure(func(name string) string {
		if name == AdminKeyEnv {
			return "configured"
		}
		return ""
	})
	for _, k := range p.Kinds() {
		if k.Revocable != (k.Kind != KindLegacy) {
			t.Errorf("%s revocable=%v with an admin key", k.Kind, k.Revocable)
		}
	}
}
