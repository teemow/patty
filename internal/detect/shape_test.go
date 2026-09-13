package detect

import "testing"

// configurable is a fake that records the environment it was configured
// from.
type configurable struct {
	fake
	got string
}

func (c *configurable) Configure(env func(string) string) { c.got = env("KEY") }

func TestConfigureReachesOnlyConfigurableProviders(t *testing.T) {
	c := &configurable{fake: fake{"cfg"}}
	plain := fake{"plain"}
	env := func(name string) string { return "value of " + name }
	got := Configure(env, plain, c)
	if len(got) != 2 || got[0] != Provider(plain) || got[1] != Provider(c) {
		t.Fatalf("Configure returned %v", got)
	}
	if c.got != "value of KEY" {
		t.Errorf("configured with %q", c.got)
	}
}

func TestHintMatches(t *testing.T) {
	value := "sk-abc-DEFGHIJKLMNOPQRSTUVWXYZ0123456789-_tail"
	for hint, want := range map[string]bool{
		"sk-abc-DEF…tail":   true,
		"sk-abc-DEF...tail": true,
		"…tail":             true,
		"sk-abc-DEF…tail1":  false,
		"sk-abd…tail":       false,
		"sk-abc-DEF…":       false,
		"sk-abc-DEF":        false,
		"…":                 false,
		"":                  false,
		value + "…" + value: false,
	} {
		if got := HintMatches(hint, value); got != want {
			t.Errorf("HintMatches(%q) = %v, want %v", hint, got, want)
		}
	}
}

func TestBoundaries(t *testing.T) {
	content := []byte("a_-x")
	if !WordBefore(content, 1) || !WordBefore(content, 2) || WordBefore(content, 3) || WordBefore(content, 0) {
		t.Error("WordBefore: letters and underscores continue a word, dashes do not")
	}
	if !Base64URLAt(content, 2) || Base64URLAt(content, 4) || !IsBase64URL('_') || IsBase64URL('.') {
		t.Error("Base64URLAt / IsBase64URL")
	}
}
