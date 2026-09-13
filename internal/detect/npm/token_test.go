package npm

import (
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

var find = New().Find

const body36 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

// accessToken builds a token of the current format at runtime.
func accessToken(body string) string {
	if len(body) != bodyLen {
		panic("body must be 36 characters")
	}
	return prefix + body
}

// uuid builds a legacy token at runtime from the hex alphabet.
func uuid() string {
	return "0123abcd" + "-" + "4567" + "-" + "89ab" + "-" + "cdef" + "-" + "0123456789ab"
}

func TestFindAccessToken(t *testing.T) {
	tok := accessToken(body36)
	content := []byte("NPM_TOKEN=" + tok + "\n")
	got := find(content)
	if len(got) != 1 || got[0].Kind != KindAccessToken || got[0].Value != tok || got[0].ChecksumVerified || got[0].Attribution != "" || got[0].Secret != "" || got[0].Offset != strings.Index(string(content), tok) {
		t.Fatalf("unexpected result %+v", got)
	}
	for name, c := range map[string]string{
		"too short":      tok[:len(tok)-1],
		"trailing alnum": tok + "x",
		"trailing _":     tok + "_",
		"inside a word":  "x" + tok,
		"non-alnum body": prefix + strings.Replace(body36, "C", "-", 1),
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindTokensInNpmrc(t *testing.T) {
	tok := accessToken(body36)
	legacy := uuid()
	npmrc := "registry=https://registry.npmjs.org/\n" +
		"//registry.npmjs.org/:_authToken=" + tok + "\n" +
		"//npm.example.com/:_authToken=" + legacy + "\n" +
		"//npm.pkg.github.com/:_authToken=ghp_notours\n" +
		"_authToken=\"" + strings.ReplaceAll(legacy, "a", "b") + "\"\n"
	got := find([]byte(npmrc))
	if len(got) != 3 {
		t.Fatalf("want the npm_ token and two UUIDs, got %+v", got)
	}
	if got[0].Kind != KindAccessToken || got[0].Value != tok || got[0].Attribution != "in an .npmrc for registry.npmjs.org" || decode(got[0]).Registry != "https://registry.npmjs.org" {
		t.Fatalf("npm_ token learns its registry: %+v", got[0])
	}
	if got[1].Kind != KindLegacyToken || got[1].Value != legacy || got[1].Attribution != "in an .npmrc for npm.example.com" || decode(got[1]).Registry != "https://npm.example.com" || got[1].Offset != strings.Index(npmrc, legacy) {
		t.Fatalf("legacy token for a private registry: %+v", got[1])
	}
	if got[2].Kind != KindLegacyToken || got[2].Attribution != "in an .npmrc for the default registry" || decode(got[2]).Registry != "" {
		t.Fatalf("bare _authToken: %+v", got[2])
	}
}

func TestUUIDNeedsAuthToken(t *testing.T) {
	legacy := uuid()
	for name, c := range map[string]string{
		"bare":             legacy,
		"other key":        "id: " + legacy,
		"upper case":       "_authToken=" + strings.ToUpper(legacy),
		"trailing alnum":   "_authToken=" + legacy + "0",
		"no equals":        "_authToken " + legacy,
		"malformed":        "_authToken=" + strings.Replace(legacy, "-", "_", 1),
		"file":             "_authTokenFile=" + legacy,
		"other provider":   "//npm.pkg.github.com/:_authToken=ghp_notours",
		"placeholder":      "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
		"empty value":      "//registry.npmjs.org/:_authToken=",
		"github-like uuid": "//registry.npmjs.org/:_authToken=" + legacy[:35],
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestKindsAreComplete(t *testing.T) {
	kinds := map[detect.Kind]bool{}
	for _, k := range New().Kinds() {
		kinds[k.Kind] = true
		if !k.Revocable || k.RevokePage == "" || k.Description == "" || k.AuditNote == "" {
			t.Errorf("%s: every npm token revokes itself and carries the audit advice: %+v", k.Kind, k)
		}
	}
	if !kinds[KindAccessToken] || !kinds[KindLegacyToken] {
		t.Fatal("a kind is missing from Kinds")
	}
}

func BenchmarkFind(b *testing.B) {
	content := []byte(strings.Repeat("some source code with npm_ in it and an _authToken mention\n", 20000))
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		find(content)
	}
}
