package grafana

import (
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"reflect"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

var find = New().Find

const secret32 = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"

// serviceAccountToken builds a well-formed token the way Grafana's
// satokengen does, from a 32-character secret.
func serviceAccountToken(secret string) string {
	if len(secret) != saSecretLen {
		panic("secret must be 32 characters")
	}
	return saPrefix + secret + "_" + Checksum(secret)
}

// cloudTokenValue encodes a Cloud token from its JSON fields, in the
// given base64 alphabet.
func cloudTokenValue(t *testing.T, enc *base64.Encoding, fields map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return cloudPrefix + enc.EncodeToString(raw)
}

// legacyKeyValue encodes a legacy API key the way apikeygen did.
func legacyKeyValue(t *testing.T, key, name string, org int64) string {
	t.Helper()
	raw, err := json.Marshal(legacyKey{Key: key, Name: name, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestChecksumMatchesSatokengen(t *testing.T) {
	// satokengen hashes "gl" + "sa" + "_" + secret and writes the four CRC
	// bytes least significant first; the expectation is derived here
	// rather than pasted, so it is transparent.
	sum := crc32.ChecksumIEEE([]byte("glsa_" + secret32))
	want := ""
	for shift := 0; shift < 32; shift += 8 {
		b := byte(sum >> shift)
		want += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}
	if got := Checksum(secret32); got != want || len(got) != saSumLen {
		t.Fatalf("Checksum = %q, want %q", got, want)
	}
}

func TestFindServiceAccountToken(t *testing.T) {
	tok := serviceAccountToken(secret32)
	content := []byte("GRAFANA_TOKEN=" + tok + "\n")
	got := find(content)
	if len(got) != 1 || got[0].Kind != KindServiceAccountToken || got[0].Value != tok || !got[0].ChecksumVerified || got[0].Offset != strings.Index(string(content), tok) {
		t.Fatalf("unexpected result %+v", got)
	}
	for name, c := range map[string]string{
		"wrong checksum":     tok[:len(tok)-1] + flip(tok[len(tok)-1]),
		"upper-case hex":     tok[:len(tok)-saSumLen] + strings.ToUpper(tok[len(tok)-saSumLen:]),
		"truncated":          tok[:len(tok)-1],
		"trailing alnum":     tok + "a",
		"inside a word":      "x" + tok,
		"missing underscore": strings.Replace(tok, "_", "X", 2),
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindCloudToken(t *testing.T) {
	fields := map[string]any{"o": "acme", "n": "ci-metrics", "k": strings.Repeat("k", 32), "m": map[string]string{"r": "prod-eu-west-2"}}
	for name, enc := range map[string]*base64.Encoding{"std": base64.StdEncoding, "raw std": base64.RawStdEncoding, "url": base64.URLEncoding, "raw url": base64.RawURLEncoding} {
		tok := cloudTokenValue(t, enc, fields)
		got := find([]byte("token: " + tok + "\n"))
		if len(got) != 1 || got[0].Kind != KindCloudToken || got[0].Value != tok || got[0].ChecksumVerified || got[0].Attribution != "org acme, token ci-metrics, region prod-eu-west-2" {
			t.Fatalf("%s: unexpected result %+v", name, got)
		}
	}
	noRegion := cloudTokenValue(t, base64.StdEncoding, map[string]any{"o": "acme", "n": "t", "k": "secret"})
	if got := find([]byte(noRegion)); len(got) != 1 || got[0].Attribution != "org acme, token t" {
		t.Fatalf("no region: %+v", got)
	}
	for name, c := range map[string]string{
		"no org":      cloudTokenValue(t, base64.StdEncoding, map[string]any{"n": "t", "k": "secret", "m": map[string]string{"r": "x"}}),
		"no key":      cloudTokenValue(t, base64.StdEncoding, map[string]any{"o": "acme", "n": "t"}),
		"not json":    cloudPrefix + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("not json at all ", 3))),
		"not base64":  cloudPrefix + strings.Repeat("!", 40),
		"too short":   cloudPrefix + base64.StdEncoding.EncodeToString([]byte(`{"o":"a","k":"b"}`)),
		"inside word": "x" + cloudTokenValue(t, base64.StdEncoding, fields),
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindLegacyAPIKey(t *testing.T) {
	key := legacyKeyValue(t, strings.Repeat("k", 32), "deploy", 3)
	if !strings.HasPrefix(key, legacyPrefix) {
		t.Fatalf("a legacy key starts with %s: %s", legacyPrefix, key)
	}
	got := find([]byte(`Authorization: Bearer ` + key + "\n"))
	if len(got) != 1 || got[0].Kind != KindLegacyAPIKey || got[0].Value != key || got[0].ChecksumVerified || got[0].Attribution != "key deploy, org id 3" {
		t.Fatalf("unexpected result %+v", got)
	}
	for name, c := range map[string]string{
		"no name":     base64.StdEncoding.EncodeToString([]byte(`{"k":"` + strings.Repeat("k", 32) + `","id":1}`)),
		"no key":      base64.StdEncoding.EncodeToString([]byte(`{"k":"","n":"deploy","id":1}`)),
		"inside word": "A" + key,
		"truncated":   key[:legacyMin-1],
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestInstances(t *testing.T) {
	content := []byte(`
url: https://grafana.example.com/api/dashboards
metrics: http://grafana.internal.example.com:3000
cloud: https://acme.grafana.net
docs: https://grafana.com/docs and https://play.grafana.org and https://grafana.github.io/
bare grafana.example.com again, and mygrafana.example.com, grafana.local, grafana.home
files: grafana.yaml grafana.ini grafana.yml; secret grafana.example.com-tls
`)
	got := New().Instances(content)
	want := []string{"https://grafana.example.com", "http://grafana.internal.example.com:3000", "https://acme.grafana.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Instances = %v, want %v", got, want)
	}
	tok := New().Bind(detect.Token{Kind: KindServiceAccountToken, Value: "v"}, got)
	if !reflect.DeepEqual(bound(tok), want) {
		t.Fatalf("Bind round trip: %v", bound(tok))
	}
	if cloud := New().Bind(detect.Token{Kind: KindCloudToken, Value: "v"}, got); cloud.Secret != "" {
		t.Fatal("a Cloud token is not bound to an instance")
	}
}

func TestSplitURLs(t *testing.T) {
	got := SplitURLs(" https://a.example.com/, http://b.example.com:3000\thttps://c.example.com ")
	want := []string{"https://a.example.com", "http://b.example.com:3000", "https://c.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitURLs = %v", got)
	}
	if SplitURLs("") != nil {
		t.Fatal("empty list")
	}
}

func TestKindsAreComplete(t *testing.T) {
	kinds := map[detect.Kind]bool{}
	for _, k := range New().Kinds() {
		kinds[k.Kind] = true
		if k.Revocable || k.Description == "" || k.RevokeNote == "" || k.AuditNote == "" {
			t.Errorf("%s: nothing here is revocable by the holder and every kind carries the owner's procedure: %+v", k.Kind, k)
		}
	}
	for _, kind := range []detect.Kind{KindServiceAccountToken, KindCloudToken, KindLegacyAPIKey} {
		if !kinds[kind] {
			t.Errorf("%s missing from Kinds", kind)
		}
	}
}

func flip(c byte) string {
	if c == 'a' {
		return "b"
	}
	return "a"
}

func BenchmarkFind(b *testing.B) {
	content := []byte(strings.Repeat("some source code with a glsa_ prefix and glc_ and eyJ in it\n", 20000))
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		find(content)
	}
}
