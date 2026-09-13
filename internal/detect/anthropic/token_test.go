package anthropic

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// body returns n random characters of the key alphabet. Every key in these
// tests is built at run time, so no key-shaped string is committed.
func body(n int) string {
	raw := make([]byte, n)
	_, _ = rand.Read(raw)
	for i, c := range raw {
		raw[i] = alphabet[int(c)%len(alphabet)]
	}
	return string(raw)
}

func newAPIKey() string   { return stem + "api03-" + body(keyBodyLen) + keySuffix }
func newAdminKey() string { return stem + "admin01-" + body(keyBodyLen) + keySuffix }
func oauth() string       { return stem + "oat01-" + body(95) }
func refresh() string     { return stem + "ort01-" + body(95) }

func find(content string) []detect.Token {
	return detect.NewRegistry(New()).Find([]byte(content))
}

func TestFindEveryFamily(t *testing.T) {
	keys := map[detect.Kind]string{KindAPIKey: newAPIKey(), KindAdminKey: newAdminKey(), KindOAuth: oauth(), KindRefresh: refresh()}
	content := "ANTHROPIC_API_KEY=" + keys[KindAPIKey] + "\nadmin: \"" + keys[KindAdminKey] + "\"\n" +
		`{"accessToken":"` + keys[KindOAuth] + `","refreshToken":"` + keys[KindRefresh] + `"}` + "\n"
	found := find(content)
	if len(found) != 4 {
		t.Fatalf("want 4 tokens, got %d: %+v", len(found), found)
	}
	for _, tok := range found {
		if keys[tok.Kind] != tok.Value {
			t.Errorf("%s: got %q", tok.Kind, tok.Value)
		}
		if tok.ChecksumVerified {
			t.Errorf("%s: no Anthropic key carries a checksum", tok.Kind)
		}
		if content[tok.Offset:tok.Offset+len(tok.Value)] != tok.Value {
			t.Errorf("%s: offset %d does not point at the token", tok.Kind, tok.Offset)
		}
	}
	if found[0].Line != 1 || found[1].Line != 2 || found[2].Line != 3 || found[3].Line != 3 {
		t.Errorf("lines: %d %d %d %d", found[0].Line, found[1].Line, found[2].Line, found[3].Line)
	}
	if len(newAPIKey()) != 108 || len(newAdminKey()) != 110 {
		t.Errorf("key lengths %d and %d", len(newAPIKey()), len(newAdminKey()))
	}
}

func TestFindRejectsNearMisses(t *testing.T) {
	key := newAPIKey()
	cases := map[string]string{
		"wrong suffix":         key[:len(key)-2] + "AB",
		"body one short":       stem + "api03-" + body(keyBodyLen-1) + keySuffix,
		"body one long":        stem + "api03-" + body(keyBodyLen+1) + keySuffix,
		"continues into word":  key + "x",
		"continues with dash":  key + "-more",
		"preceded by word":     "x" + key,
		"preceded by _":        "_" + key,
		"unknown family":       stem + "api02-" + body(keyBodyLen) + keySuffix,
		"oauth too short":      stem + "oat01-" + body(oauthMin-1),
		"oauth too long":       stem + "oat01-" + body(oauthMax+1),
		"oauth continues":      stem + "oat01-" + body(oauthMax) + "x",
		"prefix only":          stem + "api03-",
		"marker in wrong spot": stem + "api03-" + body(40) + keySuffix + body(53),
	}
	for name, content := range cases {
		if found := find(content); len(found) != 0 {
			t.Errorf("%s: matched %+v", name, found)
		}
	}
}

func TestFindAcceptsBoundaries(t *testing.T) {
	key := newAPIKey()
	for name, content := range map[string]string{
		"quoted": `"` + key + `"`, "end of text": key, "before dot": key + ".", "after equals": "key=" + key,
		"oauth min": stem + "oat01-" + body(oauthMin), "oauth max": stem + "oat01-" + body(oauthMax),
	} {
		if found := find(content); len(found) != 1 {
			t.Errorf("%s: got %+v", name, found)
		}
	}
}

func TestRedactKeepsBothEnds(t *testing.T) {
	key := newAPIKey()
	r := detect.Redact(key)
	if !strings.HasPrefix(r, "sk-ant-a") || !strings.HasSuffix(r, key[len(key)-4:]) || len(r) > 20 {
		t.Errorf("redacted %q", r)
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
	if !strings.Contains(kindInfo(p, KindAPIKey).RevokeNote, AdminKeyEnv) {
		t.Errorf("advice does not name %s: %q", AdminKeyEnv, kindInfo(p, KindAPIKey).RevokeNote)
	}
	p.Configure(func(name string) string {
		if name == AdminKeyEnv {
			return "configured"
		}
		return ""
	})
	if p.AdminKey != "configured" {
		t.Fatalf("AdminKey = %q", p.AdminKey)
	}
	for _, k := range p.Kinds() {
		if k.Revocable != (k.Kind == KindAPIKey) {
			t.Errorf("%s revocable=%v with an admin key", k.Kind, k.Revocable)
		}
	}
	if kindInfo(p, KindAPIKey).RevokeNote != "" {
		t.Errorf("configured provider still advises configuration: %q", kindInfo(p, KindAPIKey).RevokeNote)
	}
}

func kindInfo(p *Provider, kind detect.Kind) detect.KindInfo {
	return detect.NewRegistry(p).Info(kind)
}
