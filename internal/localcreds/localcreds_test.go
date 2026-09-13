package localcreds

import (
	"context"
	"encoding/base64"
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
	// A Docker config: the quay.io login is compared by host and user, the
	// entry that names a credential helper holds nothing to compare.
	if err := os.MkdirAll(filepath.Join(home, ".docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("acme+ci:" + strings.Repeat("robot", 6)))
	if err := os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{"auths":{"quay.io":{"auth":"`+auth+`"},"ghcr.io":{}},"credHelpers":{"ghcr.io":"gh"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// gcloud keeps one credential file per account under a glob, and the
	// SDKs read whatever GOOGLE_APPLICATION_CREDENTIALS names.
	adcTok, legacyTok, fileTok := gcpRefresh("Adc-"), gcpRefresh("Leg-"), gcpRefresh("Fil-")
	write("gcloud/application_default_credentials.json", gcpADC(adcTok))
	write("gcloud/legacy_credentials/jane@example.com/adc.json", gcpADC(legacyTok))
	write("gcloud/legacy_credentials/jane@example.com/.boto", "[Credentials]\n")
	write("keys/deploy.json", gcpADC(fileTok))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(cfg, "keys", "deploy.json"))

	// An Azure storage key is only a finding next to its account, which
	// another variable names; the variables are searched together.
	storageKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k3y", 21) + "!"))
	t.Setenv("AZURE_STORAGE_ACCOUNT", "examplestorage")
	t.Setenv("AZURE_STORAGE_KEY", storageKey)

	got := Match(Find(context.Background(), providers.Default()))
	if len(got) != 12 {
		t.Fatalf("Match = %v", got)
	}
	if src := got[detect.Fingerprint("quay.io/acme+ci")]; len(src) != 1 || src[0] != "~/.docker/config.json" {
		t.Errorf("registry login sources = %v", src)
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
	if src := got[detect.Fingerprint(storageKey)]; len(src) != 1 || src[0] != "$AZURE_STORAGE_KEY" {
		t.Errorf("storage key sources = %v", src)
	}
	if src := got[detect.Fingerprint(adcTok)]; len(src) != 1 || src[0] != "~/.config/gcloud/application_default_credentials.json" {
		t.Errorf("gcloud ADC sources = %v", src)
	}
	if src := got[detect.Fingerprint(legacyTok)]; len(src) != 1 || src[0] != "~/.config/gcloud/legacy_credentials/jane@example.com/adc.json" {
		t.Errorf("gcloud legacy credential sources = %v", src)
	}
	if src := got[detect.Fingerprint(fileTok)]; len(src) != 1 || src[0] != "~/.config/keys/deploy.json ($GOOGLE_APPLICATION_CREDENTIALS)" {
		t.Errorf("GOOGLE_APPLICATION_CREDENTIALS sources = %v", src)
	}
	for fp, srcs := range got {
		for _, s := range srcs {
			if strings.Contains(s, "gh"+"p_") || strings.Contains(s, "gh"+"o_") || strings.Contains(s, "xoxb"+"-") || strings.Contains(s, "AGE-SECRET") {
				t.Fatalf("source %q for %s leaks a token value", s, fp)
			}
		}
	}
}

// gcpRefresh builds a Google refresh token at runtime.
func gcpRefresh(fill string) string { return "1//0" + strings.Repeat(fill, 25) }

// gcpADC is the authorized_user document gcloud writes for an account.
func gcpADC(refresh string) string {
	return `{"type":"authorized_user","client_id":"123456789012-abc.apps.googleusercontent.com","client_secret":"d-` + strings.Repeat("s", 24) + `","refresh_token":"` + refresh + `"}`
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestFindReadsEveryKubeconfigInTheList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, p := range providers.Default().Providers() {
		src := p.LocalSources()
		for _, name := range append(src.Env, src.EnvFiles...) {
			t.Setenv(name, "")
		}
	}
	t.Setenv("PATH", t.TempDir())
	t.Chdir(t.TempDir())

	// A kubeconfig is recognised by its kind; a bearer token is enough of
	// a credential, a certificate would be compared by fingerprint the same way.
	kubeconfig := func(name, tok string) string {
		return "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://k8s.example.com:6443\ncontexts:\n- name: c\n  context:\n    cluster: c\n    user: " + name + "\nusers:\n- name: " + name + "\n  user:\n    token: " + tok + "\n"
	}
	first, second, home3 := "first-token-"+strings.Repeat("a", 20), "second-token-"+strings.Repeat("b", 20), "home-token-"+strings.Repeat("c", 20)
	paths := []string{filepath.Join(home, "one.yaml"), filepath.Join(home, "two.yaml")}
	for i, tok := range []string{first, second} {
		if err := os.WriteFile(paths[i], []byte(kubeconfig("u", tok)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".kube", "config"), []byte(kubeconfig("u", home3)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", strings.Join(paths, string(filepath.ListSeparator)))

	got := Match(Find(context.Background(), providers.Default()))
	if len(got) != 3 {
		t.Fatalf("Match = %v", got)
	}
	if src := got[detect.Fingerprint(first)]; len(src) != 1 || src[0] != "~/one.yaml ($KUBECONFIG)" {
		t.Errorf("first kubeconfig sources = %v", src)
	}
	if src := got[detect.Fingerprint(second)]; len(src) != 1 || src[0] != "~/two.yaml ($KUBECONFIG)" {
		t.Errorf("second kubeconfig sources = %v", src)
	}
	if src := got[detect.Fingerprint(home3)]; len(src) != 1 || src[0] != "~/.kube/config" {
		t.Errorf("home kubeconfig sources = %v", src)
	}
}
