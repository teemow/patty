package sops

import (
	"reflect"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestObserveSopsRules(t *testing.T) {
	a, b := identity(t).Recipient().String(), identity(t).Recipient().String()
	_, key := pgpKey(t, "D", "d@dmv.springfield", "")
	fp := Fingerprint(key.PrimaryKey)
	rules := "creation_rules:\n  - path_regex: clusters/prod/.*\n    age: >-\n      " + a + ",\n      " + b + "\n    pgp: " + strings.ToLower(fp) + "\n  - age: " + a + "\n"
	got := New().Observe([]byte(rules))
	if want := []string{a, b, fp}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Observe(.sops.yaml) = %v, want %v", got, want)
	}
}

func TestObserveEncryptedFiles(t *testing.T) {
	r := identity(t).Recipient().String()
	_, key := pgpKey(t, "E", "e@dmv.springfield", "")
	fp := Fingerprint(key.PrimaryKey)
	yaml := "password: ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\nsops:\n    age:\n        - recipient: " + r + "\n          enc: irrelevant\n    pgp:\n        - created_at: \"2026-01-01T00:00:00Z\"\n          fp: " + fp + "\n    version: 3.9.0\n"
	if got := New().Observe([]byte(yaml)); !reflect.DeepEqual(got, []string{r, fp}) {
		t.Fatalf("Observe(yaml) = %v", got)
	}
	// JSON puts quotes between "sops" and the colon; the ENC[ marker still applies.
	js := `{"password": "ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]", "sops": {"age": [{"recipient": "` + r + `"}]}}`
	if got := New().Observe([]byte(js)); !reflect.DeepEqual(got, []string{r}) {
		t.Fatalf("Observe(json) = %v", got)
	}
	// A metadata block without encrypted values (sops --extract, or a stub).
	meta := "sops:\n  age:\n  - recipient: " + r + "\n"
	if got := New().Observe([]byte(meta)); !reflect.DeepEqual(got, []string{r}) {
		t.Fatalf("Observe(metadata) = %v", got)
	}
}

func TestObserveIgnoresOtherContent(t *testing.T) {
	id := identity(t)
	r := id.Recipient().String()
	cases := map[string]string{
		"identity file": "# created: 2026-01-01\n# public key: " + r + "\n" + id.String() + "\n",
		"readme":        "Encrypt secrets to " + r + " before committing.\n",
		"empty":         "",
		"unrelated":     "sops: is a tool\nage: 42\n",
	}
	for name, c := range cases {
		if got := New().Observe([]byte(c)); got != nil {
			t.Errorf("%s: want nil, got %v", name, got)
		}
	}
}

func TestObserveChecksRecipientsAndBoundaries(t *testing.T) {
	r := identity(t).Recipient().String()
	bad := r[:len(r)-1] + map[bool]string{true: "p", false: "q"}[r[len(r)-1] == 'q']
	content := "creation_rules:\n- age: " + bad + "\n- age: x" + r + "\n- age: " + r + "z\n- pgp: " + strings.Repeat("A", 39) + "\n- pgp: " + strings.Repeat("B", 41) + "\n- pgp: X" + strings.Repeat("C", 40) + "\n"
	if got := New().Observe([]byte(content)); got != nil {
		t.Fatalf("lookalikes must not count as recipients, got %v", got)
	}
	// A fingerprint is only looked for when the file mentions pgp at all.
	content = "creation_rules:\n- age: " + r + "\n- key: " + strings.Repeat("D", 40) + "\n"
	if got := New().Observe([]byte(content)); !reflect.DeepEqual(got, []string{r}) {
		t.Fatalf("hex without pgp context, got %v", got)
	}
}

func TestIdentifiers(t *testing.T) {
	id := identity(t)
	p := New()
	if got := p.Identifiers(detect.Token{Kind: KindAge, Value: id.String()}); !reflect.DeepEqual(got, []string{id.Recipient().String()}) {
		t.Fatalf("age identifiers = %v", got)
	}
	if got := p.Identifiers(detect.Token{Kind: KindAge, Value: corrupt(id.String())}); got != nil {
		t.Fatalf("corrupted identity has no identifier, got %v", got)
	}
	fp := strings.Repeat("ab", 20)
	if got := p.Identifiers(detect.Token{Kind: KindPGP, Value: fp}); !reflect.DeepEqual(got, []string{strings.ToUpper(fp)}) {
		t.Fatalf("pgp identifiers = %v", got)
	}
	if got := p.Identifiers(detect.Token{Kind: "github-pat", Value: "x"}); got != nil {
		t.Fatalf("foreign kind, got %v", got)
	}
}
