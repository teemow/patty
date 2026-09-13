package localcreds

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/providers"
)

// token builds a well-formed classic token at runtime so none is committed.
func token(kind byte, random string) string {
	return "gh" + string(kind) + "_" + random + github.Checksum(random)
}

// slackBot builds a well-formed bot token at runtime.
func slackBot(secret string) string {
	return "xoxb-" + "1234567890" + "-" + "1234567890123" + "-" + secret
}

// ageIdentity generates an age identity at runtime.
func ageIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFind(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	for _, p := range providers.Default().Providers() {
		src := p.LocalSources()
		for _, name := range append(src.Env, src.EnvFiles...) {
			t.Setenv(name, "")
		}
	}
	t.Setenv("PATH", t.TempDir()) // no gh on the PATH
	t.Chdir(t.TempDir())

	hubTok := token('p', "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ghTok := token('o', "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	envTok := token('p', "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	slackTok := slackBot(strings.Repeat("Ab", 12))
	slackEnv := slackBot(strings.Repeat("Cd", 12))
	write := func(rel, content string) {
		path := filepath.Join(cfg, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("hub", "github.com:\n- user: patty\n  oauth_token: "+hubTok+"\n")
	write("gh/hosts.yml", "github.com:\n    oauth_token: "+ghTok+"\n    user: patty\n")
	write("github-copilot/hosts.json", `{"github.com":{"oauth_token":"not a token"}}`)
	if err := os.MkdirAll(filepath.Join(home, ".slack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".slack", "credentials.json"), []byte(`{"team":{"token":"`+slackTok+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_TOKEN", envTok)
	t.Setenv("SLACK_BOT_TOKEN", slackEnv)
	// An identity file both listed by the provider and named by the
	// variable is one source, labelled with the variable.
	fileID, envID := ageIdentity(t), ageIdentity(t)
	write("sops/age/keys.txt", "# public key: "+fileID.Recipient().String()+"\n"+fileID.String()+"\n")
	t.Setenv("SOPS_AGE_KEY_FILE", filepath.Join(cfg, "sops", "age", "keys.txt"))
	t.Setenv("SOPS_AGE_KEY", envID.String())
	if err := os.WriteFile(".env", []byte("GITHUB_TOKEN="+hubTok+"\nSLACK_TOKEN="+slackTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := Match(Find(context.Background(), providers.Default()))
	if len(got) != 7 {
		t.Fatalf("Match = %v", got)
	}
	if src := got[detect.Fingerprint(fileID.String())]; len(src) != 1 || src[0] != "~/.config/sops/age/keys.txt ($SOPS_AGE_KEY_FILE)" {
		t.Errorf("identity file sources = %v", src)
	}
	if src := got[detect.Fingerprint(envID.String())]; len(src) != 1 || src[0] != "$SOPS_AGE_KEY" {
		t.Errorf("identity env sources = %v", src)
	}
	if src := strings.Join(got[detect.Fingerprint(hubTok)], ","); src != "~/.config/hub,"+mustAbs(t, ".env") {
		t.Errorf("hub token sources = %q", src)
	}
	if src := got[detect.Fingerprint(ghTok)]; len(src) != 1 || src[0] != "~/.config/gh/hosts.yml" {
		t.Errorf("gh token sources = %v", src)
	}
	if src := got[detect.Fingerprint(envTok)]; len(src) != 1 || src[0] != "$GH_TOKEN" {
		t.Errorf("env token sources = %v", src)
	}
	if src := strings.Join(got[detect.Fingerprint(slackTok)], ","); src != "~/.slack/credentials.json,"+mustAbs(t, ".env") {
		t.Errorf("slack token sources = %q", src)
	}
	if src := got[detect.Fingerprint(slackEnv)]; len(src) != 1 || src[0] != "$SLACK_BOT_TOKEN" {
		t.Errorf("slack env token sources = %v", src)
	}
	for fp, srcs := range got {
		for _, s := range srcs {
			if strings.Contains(s, "gh"+"p_") || strings.Contains(s, "gh"+"o_") || strings.Contains(s, "xoxb"+"-") || strings.Contains(s, "AGE-SECRET") {
				t.Fatalf("source %q for %s leaks a token value", s, fp)
			}
		}
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
