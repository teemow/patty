package gitlab

import (
	"bytes"
	"encoding/base64"
	"hash/crc32"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

var find = New().Find

// body returns n characters of the token alphabet, never a real token.
func body(n int) string {
	const alphabet = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_"
	return strings.Repeat(alphabet, n/len(alphabet)+1)[:n]
}

// routable builds a routable token the way GitLab's generator does, with
// fixed random bytes: prefix, base64url of random + payload + size byte,
// a dot, the version segment when versioned, the base64 length in two
// base36 digits and the CRC32 of everything before it in seven.
func routable(prefix, payload string, versioned bool) string {
	raw := append(bytes.Repeat([]byte{0xAB}, routableRandomLen), payload...)
	raw = append(raw, byte(len(payload)))
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	encoded := prefix + b64 + "."
	if versioned {
		encoded += "01."
	}
	encoded += RoutableLength(len(b64))
	return encoded + RoutableChecksum(encoded)
}

func TestRoutableChecksumMatchesGitLab(t *testing.T) {
	// Zlib.crc32(encoded).to_s(36).rjust(7, '0'): derived here, not pasted.
	encoded := "glpat-" + body(30) + ".01.0u"
	want := strconv.FormatUint(uint64(crc32.ChecksumIEEE([]byte(encoded))), 36)
	want = strings.Repeat("0", routableCRCLen-len(want)) + want
	if got := RoutableChecksum(encoded); got != want {
		t.Fatalf("RoutableChecksum = %q, want %q", got, want)
	}
	if RoutableLength(30) != "0u" || RoutableLength(36) != "10" {
		t.Fatalf("length holder: %q %q", RoutableLength(30), RoutableLength(36))
	}
}

func TestFindRoutablePAT(t *testing.T) {
	payload := "c:1\ng:a\no:2\nu:z"
	for name, versioned := range map[string]bool{"versioned": true, "first layout": false} {
		tok := routable("glpat-", payload, versioned)
		content := []byte("GITLAB_TOKEN=" + tok + "\n")
		got := find(content)
		if len(got) != 1 || got[0].Kind != KindPAT || got[0].Value != tok || !got[0].ChecksumVerified || got[0].Offset != strings.Index(string(content), tok) {
			t.Fatalf("%s: unexpected result %+v", name, got)
		}
		if got[0].Attribution != "cell 1, group 10, organization 2, user 35" {
			t.Fatalf("%s: attribution %q", name, got[0].Attribution)
		}
	}
	tok := routable("glpat-", "o:1\np:2f\nt:pat", true)
	if got := find([]byte(tok)); len(got) != 1 || got[0].Attribution != "organization 1, project 87, type pat" {
		t.Fatalf("type is kept as written: %+v", got)
	}
}

func TestFindRejectsCorruptedRoutablePAT(t *testing.T) {
	tok := routable("glpat-", "c:1\no:2", true)
	bad := func(s string, at int) string { return s[:at] + flip(s[at]) + s[at+1:] }
	for name, c := range map[string]string{
		"wrong crc":         bad(tok, len(tok)-1),
		"wrong length":      bad(tok, len(tok)-routableCRCLen-1),
		"edited version":    strings.Replace(tok, ".01.", ".02.", 1), // the crc no longer holds
		"payload edited":    bad(tok, len("glpat-")+24),
		"truncated":         tok[:len(tok)-1],
		"trailing alnum":    tok + "x",
		"inside a word":     "x" + tok,
		"unknown key":       routable("glpat-", "c:1\nq:2", true),
		"non-base36 value":  routable("glpat-", "c:1\no:2!", true),
		"size byte wrong":   corruptSize(t),
		"empty payload":     routable("glpat-", "", true),
		"other prefix only": "glpat-",
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

// corruptSize builds a token whose size byte does not match its payload,
// with a checksum that still holds, so only the payload check rejects it.
func corruptSize(t *testing.T) string {
	t.Helper()
	raw := append(bytes.Repeat([]byte{0xAB}, routableRandomLen), "c:1\no:2"...)
	raw = append(raw, 3)
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	encoded := "glpat-" + b64 + ".01." + RoutableLength(len(b64))
	return encoded + RoutableChecksum(encoded)
}

func TestFindLegacyPAT(t *testing.T) {
	tok := "glpat-" + body(20)
	got := find([]byte("token: " + tok + "\n"))
	if len(got) != 1 || got[0].Kind != KindPAT || got[0].Value != tok || got[0].ChecksumVerified || got[0].Attribution != "" {
		t.Fatalf("unexpected result %+v", got)
	}
	for name, c := range map[string]string{
		"too short":      tok[:len(tok)-1],
		"too long":       tok + "a",
		"trailing dash":  tok + "-",
		"inside a word":  "a" + tok,
		"wrong alphabet": "glpat-" + strings.Replace(body(20), "C", "+", 1),
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindEveryFamily(t *testing.T) {
	cases := map[detect.Kind]string{
		KindDeployToken:            "gldt-" + body(20),
		KindRunnerToken:            "glrt-" + body(20),
		KindJobToken:               "glcbt-1a_" + body(20),
		KindTriggerToken:           "glptt-" + strings.Repeat("0123456789abcdef", 3)[:40],
		KindFeedToken:              "glft-" + body(20),
		KindIncomingMailToken:      "glimt-" + body(25),
		KindAgentToken:             "glagent-" + body(50),
		KindOAuthAppSecret:         "gloas-" + body(64),
		KindFeatureFlagClientToken: "glffct-" + body(20),
		KindSCIMToken:              "glsoat-" + body(20),
	}
	for kind, tok := range cases {
		content := []byte("x = '" + tok + "'\n")
		got := find(content)
		if len(got) != 1 || got[0].Kind != kind || got[0].Value != tok || got[0].ChecksumVerified || got[0].Offset != strings.Index(string(content), tok) {
			t.Errorf("%s: unexpected result %+v", kind, got)
		}
		if got := find([]byte(tok + "a")); len(got) != 0 {
			t.Errorf("%s: a longer run is not a token, got %+v", kind, got)
		}
		if got := find([]byte(tok[:len(tok)-1])); len(got) != 0 {
			t.Errorf("%s: a shorter run is not a token, got %+v", kind, got)
		}
	}
	all := make([]string, 0, len(cases))
	for _, tok := range cases {
		all = append(all, tok)
	}
	if got := find([]byte(strings.Join(all, "\n"))); len(got) != len(cases) {
		t.Fatalf("want %d tokens, got %d", len(cases), len(got))
	}
	for name, c := range map[string]string{
		"trigger upper hex": "glptt-" + strings.ToUpper(strings.Repeat("0123456789abcdef", 3)[:40]),
		"job no partition":  "glcbt-" + body(20),
		"job long part":     "glcbt-123456_" + body(20),
		"unknown prefix":    "glxyz-" + body(20),
		"glob is a word":    "glob-" + body(20),
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindRoutableRunnerToken(t *testing.T) {
	tok := routable("glrt-t1_", "c:1\np:5", true)
	got := find([]byte("runner:\n  token: " + tok + "\n"))
	if len(got) != 1 || got[0].Kind != KindRunnerToken || got[0].Value != tok || !got[0].ChecksumVerified || got[0].Attribution != "cell 1, project 5" {
		t.Fatalf("unexpected result %+v", got)
	}
	if got := find([]byte(tok[:len(tok)-1] + flip(tok[len(tok)-1]))); len(got) != 0 {
		t.Fatalf("wrong checksum: %+v", got)
	}
}

func TestDeployTokenLearnsItsUsername(t *testing.T) {
	tok := "gldt-" + body(20)
	got := find([]byte("docker login -u gitlab+deploy-token-42 -p " + tok + " registry.gitlab.example.com\n"))
	if len(got) != 1 || got[0].Attribution != "username gitlab+deploy-token-42" || decode(got[0]).Username != "gitlab+deploy-token-42" {
		t.Fatalf("with username: %+v", got)
	}
	got = find([]byte("DEPLOY_TOKEN=" + tok + "\n"))
	if len(got) != 1 || got[0].Attribution != "username not found nearby" || got[0].Secret != "" {
		t.Fatalf("without username: %+v", got)
	}
}

func TestInstances(t *testing.T) {
	content := []byte(`
remote: https://gitlab.example.com/acme/app.git
mirror: http://gitlab.internal.example.com:8443/acme
also gitlab.com, https://registry.gitlab.com, https://docs.gitlab.com, acme.gitlab.io, mygitlab.example.com
`)
	got := New().Instances(content)
	want := []string{"https://gitlab.example.com", "http://gitlab.internal.example.com:8443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Instances = %v, want %v", got, want)
	}
	tok := New().Bind(detect.Token{Kind: KindDeployToken, Value: "v", Secret: companion{Username: "gitlab+deploy-token-1"}.encode()}, got)
	if c := decode(tok); c.Username != "gitlab+deploy-token-1" || !reflect.DeepEqual(c.Instances, want) {
		t.Fatalf("Bind keeps the username: %+v", c)
	}
}

func TestKindsAreComplete(t *testing.T) {
	kinds := map[detect.Kind]bool{}
	for _, k := range New().Kinds() {
		kinds[k.Kind] = true
		if k.Description == "" || k.RevokeNote == "" || k.AuditNote == "" {
			t.Errorf("%s: incomplete %+v", k.Kind, k)
		}
		if k.Revocable != (k.Kind == KindPAT) {
			t.Errorf("%s: personal access tokens are the only kind that revokes itself", k.Kind)
		}
	}
	for _, f := range families {
		if !kinds[f.kind] {
			t.Errorf("%s missing from Kinds", f.kind)
		}
	}
}

func flip(c byte) string {
	if c == 'a' || c == 'A' || c == '0' {
		return "b"
	}
	return "a"
}

func BenchmarkFind(b *testing.B) {
	content := []byte(strings.Repeat("some source code with glob and single and glpat in it\n", 20000))
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		find(content)
	}
}
