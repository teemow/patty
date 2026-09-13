package detect

import (
	"encoding/base64"
	"strings"
	"testing"
)

// manifest assembles a Secret manifest at runtime; data values are
// base64-encoded here, stringData values written as they are.
func manifest(ns, name string, data, stringData map[string]string, extra string) string {
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: " + "Secret\nmetadata:\n  name: " + name + "\n")
	if ns != "" {
		b.WriteString("  namespace: " + ns + "\n")
	}
	b.WriteString("type: Opaque\n" + extra)
	if len(data) > 0 {
		b.WriteString("data:\n")
		for k, v := range data {
			b.WriteString("  " + k + ": " + base64.StdEncoding.EncodeToString([]byte(v)) + "\n")
		}
	}
	if len(stringData) > 0 {
		b.WriteString("stringData:\n")
		for k, v := range stringData {
			b.WriteString("  " + k + ": " + v + "\n")
		}
	}
	return b.String()
}

func TestSecretsDecodesDataAndStringData(t *testing.T) {
	content := "# leading comment\n" + manifest("prod", "api", map[string]string{"token": "alpha-value"}, map[string]string{"plain": "beta-value", "empty": `""`}, "")
	got := Secrets([]byte(content))
	if len(got) != 1 {
		t.Fatalf("Secrets = %+v", got)
	}
	s := got[0]
	if s.Ref() != "prod/api" || s.Sops || s.Type != "Opaque" || len(s.Values) != 3 {
		t.Fatalf("secret %+v", s)
	}
	byKey := map[string]SecretValue{}
	for _, v := range s.Values {
		byKey[v.Key] = v
	}
	if string(byKey["token"].Value) != "alpha-value" || string(byKey["plain"].Value) != "beta-value" || byKey["empty"].Skipped != "empty" {
		t.Fatalf("values %+v", byKey)
	}
	if strings.Count(content[:byKey["token"].Offset], "\n")+1 != 9 || !strings.HasPrefix(content[byKey["token"].Offset:], "token:") {
		t.Fatalf("token key offset %d points at %q", byKey["token"].Offset, content[byKey["token"].Offset:byKey["token"].Offset+6])
	}
	if !strings.HasPrefix(content[s.Offset:], "Secret") {
		t.Fatalf("manifest offset %d points at %q", s.Offset, content[s.Offset:s.Offset+6])
	}
	if len(s.Plaintext()) != 2 {
		t.Fatalf("plaintext %+v", s.Plaintext())
	}
}

func TestSecretsSkipsWhatIsNotMaterial(t *testing.T) {
	enc := manifest("prod", "enc", nil, map[string]string{"token": "ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]"}, "sops:\n  version: 3.8.1\n  age:\n  - recipient: age1example\n")
	got := Secrets([]byte(enc))
	if len(got) != 1 || !got[0].Sops || got[0].Values[0].Skipped != "encrypted" {
		t.Fatalf("sops secret: %+v", got)
	}
	tpl := manifest("", "tpl", nil, map[string]string{"a": `"{{ .Values.password }}"`, "b": `"${PASSWORD}"`, "c": `".Values.token"`}, "")
	tpl += "data:\n  d: {{ .Values.encoded | b64enc }}\n  e: not-base64!\n"
	got = Secrets([]byte(tpl))
	if len(got) != 1 || got[0].Ref() != "tpl" || len(got[0].Plaintext()) != 0 {
		t.Fatalf("templated secret: %+v", got)
	}
	for _, v := range got[0].Values {
		switch v.Key {
		case "a", "b", "c", "d":
			if v.Skipped != "templated" {
				t.Errorf("%s: %+v", v.Key, v)
			}
		case "e":
			if v.Skipped != "not base64" {
				t.Errorf("%s: %+v", v.Key, v)
			}
		}
	}
	huge := manifest("", "big", map[string]string{"blob": strings.Repeat("x", maxSecretValue+1)}, nil, "")
	if got = Secrets([]byte(huge)); len(got) != 1 || got[0].Values[0].Skipped != "too large" {
		t.Fatalf("oversized value: %+v", got)
	}
	for _, content := range []string{"kind: ConfigMap\ndata:\n  a: b\n", "SecretAccessKey: kind\n", "the kind of secret\n", "{{ if .Values.x }}\nkind: Secret\n{{ end }}\n"} {
		if got := Secrets([]byte(content)); got != nil {
			t.Errorf("%q: %+v", content, got)
		}
	}
}

func TestSecretsMultiDocumentListAndJSON(t *testing.T) {
	content := "---\n" + manifest("a", "one", map[string]string{"k": "v1"}, nil, "") + "---\nkind: Deployment\nspec: {{ broken\n---\n" + manifest("b", "two", map[string]string{"k": "v2"}, nil, "") + "---\n"
	got := Secrets([]byte(content))
	if len(got) != 2 || got[0].Ref() != "a/one" || got[1].Ref() != "b/two" || string(got[1].Values[0].Value) != "v2" {
		t.Fatalf("multi-document: %+v", got)
	}
	if off := got[1].Values[0].Offset; off < strings.Index(content, "name: two") || !strings.HasPrefix(content[off:], "k:") {
		t.Fatalf("second document's key offset %d points at %q", off, content[off:off+2])
	}
	list := `{"apiVersion":"v1","kind":"List","items":[{"kind":"Secret","metadata":{"name":"j","namespace":"ns"},"data":{"k":"` + base64.StdEncoding.EncodeToString([]byte("v3")) + `"}},{"kind":"ConfigMap"}]}`
	got = Secrets([]byte(list))
	if len(got) != 1 || got[0].Ref() != "ns/j" || string(got[0].Values[0].Value) != "v3" || got[0].Values[0].Offset != strings.Index(list, `"k":`) {
		t.Fatalf("list: %+v", got)
	}
}

func TestHasKind(t *testing.T) {
	for content, want := range map[string]bool{
		"kind: Secret\n":         true,
		`{"kind": "Secret"}`:     true,
		`{"kind":"Secret"}`:      true,
		"kind:   'Secret'\n":     true,
		"kind: SecretStore\n":    false,
		"unkind: Secret\n":       false,
		"Secret\n":               false,
		"kind: Config\nkind: X":  false,
		"a: b\nkind: Config\n":   false,
		"kind: Config\nSecret\n": false,
	} {
		if HasKind([]byte(content), "Secret") != want {
			t.Errorf("HasKind(%q) = %v", content, !want)
		}
	}
}

func TestRegistryRescansSecretValues(t *testing.T) {
	r := NewRegistry(fake{"alpha"}, fake{"beta"})
	content := "# alpha\n" + manifest("prod", "api", map[string]string{"one": "has alpha inside", "two": "and beta"}, map[string]string{"three": "beta"}, "")
	got := r.Find([]byte(content))
	if len(got) != 4 {
		t.Fatalf("want alpha in the comment, alpha and beta from data, beta from stringData once, got %+v", got)
	}
	// The alpha in the comment is its own occurrence, without context.
	if got[0].Value != "alpha" || got[0].Line != 1 || got[0].Attribution != "" {
		t.Fatalf("alpha in comment: %+v", got[0])
	}
	byKey := map[string]Token{}
	for _, tok := range got[1:] {
		byKey[strings.TrimPrefix(tok.Attribution, "in Secret prod/api, key ")] = tok
	}
	if tok := byKey["one"]; tok.Value != "alpha" || !strings.HasPrefix(content[tok.Offset:], "one:") {
		t.Fatalf("alpha in data: %+v", byKey)
	}
	if tok := byKey["two"]; tok.Value != "beta" || !strings.HasPrefix(content[tok.Offset:], "two:") {
		t.Fatalf("beta in data: %+v", byKey)
	}
	// stringData is seen by the providers in the clear and by the rescan:
	// one finding, at the provider's offset, with the Secret context.
	if tok := byKey["three"]; tok.Value != "beta" || !strings.HasPrefix(content[tok.Offset:], "beta") {
		t.Fatalf("beta in stringData: %+v", byKey)
	}
	if InSecret("ns/n", "k", "team 1") != "in Secret ns/n, key k (team 1)" {
		t.Fatal("InSecret with an attribution")
	}
}

func TestRegistryRescanSkipsSopsAndDepth(t *testing.T) {
	r := NewRegistry(fake{"alpha"})
	sops := manifest("p", "s", map[string]string{"k": "alpha"}, map[string]string{"e": "ENC[AES256_GCM,data:xyz,type:str]"}, "sops:\n  version: 3\n")
	if got := r.Find([]byte(sops)); got != nil {
		t.Fatalf("sops document must yield nothing, got %+v", got)
	}
	// A Secret manifest inside a Secret value is one layer too deep: the
	// inner manifest's values are not decoded again.
	inner := manifest("p", "inner", map[string]string{"k": "alpha"}, nil, "")
	outer := manifest("p", "outer", map[string]string{"manifest": inner}, nil, "")
	if got := r.Find([]byte(outer)); got != nil {
		t.Fatalf("second base64 layer must not be decoded, got %+v", got)
	}
}

// serverVerifying is a fake that records the private-server setting.
type serverVerifying struct {
	fake
	allow *bool
}

func (s serverVerifying) AllowPrivateServers(allow bool) { *s.allow = allow }

func TestRegistryAllowPrivateServers(t *testing.T) {
	var allow bool
	r := NewRegistry(fake{"alpha"}, serverVerifying{fake{"beta"}, &allow})
	r.AllowPrivateServers(true)
	if !allow {
		t.Fatal("the setting must reach every ServerVerifier")
	}
}
