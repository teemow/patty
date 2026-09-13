package registry

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/github"
)

// Every credential below is assembled at runtime so nothing token-shaped
// is committed.
var (
	hubPAT   = "dckr_" + "pat_" + strings.Repeat("Ab1", 9)
	hubOAT   = "dckr_" + "oat_" + strings.Repeat("Cd2", 9)
	robotTok = strings.Repeat("QR7", 21) + "X"
	oauthTok = strings.Repeat("Qa1z", 10)
	ghpTok   = "ghp_" + strings.Repeat("A", 30) + github.Checksum(strings.Repeat("A", 30))
)

var find = New(github.New()).Find

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// config renders a Docker config with the given auths map and extra
// top-level fields.
func config(t *testing.T, auths map[string]map[string]string, extra map[string]any) string {
	t.Helper()
	doc := map[string]any{"auths": auths}
	for k, v := range extra {
		doc[k] = v
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func want(t *testing.T, got []detect.Token, kind detect.Kind, value, secret string) detect.Token {
	t.Helper()
	for _, tok := range got {
		if tok.Kind == kind && tok.Value == value {
			if tok.Secret != secret {
				t.Errorf("%s %s: secret %q, want %q", kind, value, tok.Secret, secret)
			}
			return tok
		}
	}
	t.Errorf("%s %s not found in %+v", kind, value, got)
	return detect.Token{}
}

func TestFindDockerConfig(t *testing.T) {
	content := config(t, map[string]map[string]string{
		"quay.io":                     {"auth": b64("acme+ci:" + strings.Repeat("s3cret", 4))},
		"ghcr.io":                     {"username": "octocat", "password": ghpTok},
		"registry.example.com:5000":   {"auth": b64("deploy:hunter2hunter2")},
		"https://index.docker.io/v1/": {"username": "alice", "password": "plainpassword1"},
		"gcr.io":                      {},
		"myregistry.azurecr.io":       {"username": "myregistry", "password": "acr-admin-password-x"},
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com": {"auth": b64("AWS:eyJwYXlsb2FkIjoi" + strings.Repeat("ECR", 40))},
	}, map[string]any{"credsStore": "desktop", "credHelpers": map[string]string{"gcr.io": "gcloud"}})
	got := find([]byte(content))
	if len(got) != 6 {
		t.Fatalf("want 6 logins (the credHelper entry holds no secret), got %d: %+v", len(got), got)
	}
	quay := want(t, got, KindQuayLogin, "quay.io/acme+ci", strings.Repeat("s3cret", 4))
	if quay.Attribution != "quay.io, user acme+ci" {
		t.Errorf("quay attribution %q", quay.Attribution)
	}
	ghcr := want(t, got, KindGHCRLogin, "ghcr.io/octocat", ghpTok)
	if ghcr.Attribution != "ghcr.io, user octocat, password is a GitHub personal access token (classic), reported separately" {
		t.Errorf("ghcr attribution %q", ghcr.Attribution)
	}
	want(t, got, KindRegistryLogin, "registry.example.com:5000/deploy", "hunter2hunter2")
	want(t, got, KindHubLogin, "index.docker.io/alice", "plainpassword1")
	want(t, got, KindACRLogin, "myregistry.azurecr.io/myregistry", "acr-admin-password-x")
	ecr := want(t, got, KindECRLogin, "123456789012.dkr.ecr.eu-west-1.amazonaws.com/AWS", "eyJwYXlsb2FkIjoi"+strings.Repeat("ECR", 40))
	if !strings.Contains(ecr.Attribution, "temporary") {
		t.Errorf("ecr attribution %q should say the password is temporary", ecr.Attribution)
	}
	for _, tok := range got {
		if tok.Kind == github.KindPAT {
			t.Error("a password in the clear is the GitHub provider's finding, not ours")
		}
		if tok.Offset <= 0 || tok.Offset >= len(content) {
			t.Errorf("%s: offset %d outside the content", tok.Value, tok.Offset)
		}
	}
	if quay.Offset != strings.Index(content, `"quay.io"`) {
		t.Errorf("quay offset %d, want the entry's key at %d", quay.Offset, strings.Index(content, `"quay.io"`))
	}
}

func TestFindCredsStoreOnlyYieldsNothing(t *testing.T) {
	content := config(t, map[string]map[string]string{"quay.io": {}, "ghcr.io": {}}, map[string]any{"credsStore": "osxkeychain"})
	if got := find([]byte(content)); got != nil {
		t.Fatalf("a config that keeps its secrets in the keychain has nothing to report, got %+v", got)
	}
}

func TestFindPullSecretManifest(t *testing.T) {
	inner := config(t, map[string]map[string]string{"ghcr.io": {"auth": b64("octocat:" + ghpTok)}}, nil)
	manifest := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: pull\ntype: kubernetes.io/dockerconfigjson\ndata:\n  .dockerconfigjson: " + b64(inner) + "\n"
	got := detect.NewRegistry(github.New(), New(github.New())).Find([]byte(manifest))
	if len(got) != 2 {
		t.Fatalf("want the login and the GitHub token hidden in it, got %+v", got)
	}
	login := want(t, got, KindGHCRLogin, "ghcr.io/octocat", ghpTok)
	pat := want(t, got, github.KindPAT, ghpTok, "")
	if login.Line != 7 || pat.Line != 7 {
		t.Errorf("both belong on the .dockerconfigjson line 7, got %d and %d", login.Line, pat.Line)
	}
	if !strings.Contains(login.Attribution, "password is a GitHub personal access token (classic), reported separately") {
		t.Errorf("attribution %q", login.Attribution)
	}
}

func TestFindHelmValuesInline(t *testing.T) {
	// A config as an escaped JSON string: the way a values file carries
	// it when it is not base64.
	escaped, _ := json.Marshal(config(t, map[string]map[string]string{"quay.io": {"username": "acme+ci", "password": robotTok}}, nil))
	values := "imagePullSecret:\n  dockerconfigjson: " + string(escaped) + "\n"
	got := find([]byte(values))
	if len(got) != 1 {
		t.Fatalf("the robot token is one finding whether the decoder or the bare scan sees it, got %+v", got)
	}
	robot := want(t, got, KindQuayRobot, robotTok, "acme+ci")
	if robot.Attribution != "quay.io, user acme+ci" {
		t.Errorf("attribution %q", robot.Attribution)
	}
	// The same as base64 under a Helm value.
	values = "imagePullSecret:\n  dockerconfigjson: " + b64(config(t, map[string]map[string]string{"https://index.docker.io/v1/": {"auth": b64("alice:" + hubPAT)}}, nil)) + "\n"
	got = find([]byte(values))
	if len(got) != 1 {
		t.Fatalf("want one Docker Hub token, got %+v", got)
	}
	want(t, got, KindHubPAT, hubPAT, "alice")
	// Two layers is the limit: a base64 blob inside a base64 blob is not
	// something Kubernetes or Helm produce.
	deep := b64("data:\n  .dockerconfigjson: " + b64(config(t, map[string]map[string]string{"quay.io": {"auth": b64("a:b")}}, nil)))
	if got := find([]byte("dockerconfigjson: " + deep)); got != nil {
		t.Errorf("a third base64 layer must not be decoded, got %+v", got)
	}
}

func TestFindHubTokens(t *testing.T) {
	cases := []struct {
		name, content, user string
		kind                detect.Kind
	}{
		{"env", "DOCKER_USERNAME=alice\nDOCKER_PASSWORD=" + hubPAT + "\n", "alice", KindHubPAT},
		{"json", `{"username": "carol", "password": "` + hubPAT + `"}`, "carol", KindHubPAT},
		{"cli", "docker login -u bob -p " + hubPAT + " docker.io", "bob", KindHubPAT},
		{"yaml", "user: dave\ntoken: " + hubPAT, "dave", KindHubPAT},
		{"alone", "token: " + hubPAT, "", KindHubPAT},
		{"org", "username: acme\npassword: " + hubOAT, "acme", KindHubOAT},
		{"variable", "docker login -u ${DOCKER_USER} -p " + hubPAT, "", KindHubPAT},
	}
	for _, c := range cases {
		got := find([]byte(c.content))
		if len(got) != 1 {
			t.Errorf("%s: want 1 token, got %+v", c.name, got)
			continue
		}
		tok := got[0]
		if tok.Kind != c.kind || tok.Secret != c.user {
			t.Errorf("%s: got %s with user %q, want %s with %q", c.name, tok.Kind, tok.Secret, c.kind, c.user)
		}
		wantAttr := "user " + c.user
		if c.user == "" {
			wantAttr = "username not found nearby"
		}
		if tok.Attribution != wantAttr {
			t.Errorf("%s: attribution %q, want %q", c.name, tok.Attribution, wantAttr)
		}
	}
	for _, bad := range []string{"x" + hubPAT, hubPAT + "0123456789abcdefgh", "dckr_pat_short", hubPAT[:len(hubPAT)-10]} {
		if got := find([]byte(bad)); got != nil {
			t.Errorf("%q is not a token, got %+v", bad, got)
		}
	}
}

func TestFindQuayTokens(t *testing.T) {
	if got := find([]byte("robot: acme+deploy\ntoken: " + robotTok + "\n")); len(got) != 1 || got[0].Kind != KindQuayRobot || got[0].Secret != "acme+deploy" || got[0].Attribution != "robot acme+deploy" {
		t.Errorf("robot token with its name: %+v", got)
	}
	if got := find([]byte("token: " + robotTok + "\n")); got != nil {
		t.Errorf("a robot token without its robot is noise, got %+v", got)
	}
	hex := strings.Repeat("ABCDEF01", 8)
	if got := find([]byte("robot: acme+deploy\nsha256: " + hex + "\n")); got != nil {
		t.Errorf("a hash is not a robot token, got %+v", got)
	}
	if got := find([]byte("# base64 " + b64("acme+deploy sees") + "\ntoken: " + robotTok + "\n")); got != nil {
		t.Errorf("a plus inside base64 is not a robot name, got %+v", got)
	}
	if got := find([]byte("QUAY_TOKEN=" + oauthTok + " # for quay.io\n")); len(got) != 1 || got[0].Kind != KindQuayOAuth || got[0].Value != oauthTok {
		t.Errorf("OAuth token near quay.io: %+v", got)
	}
	if got := find([]byte("TOKEN=" + oauthTok + "\n")); got != nil {
		t.Errorf("40 alphanumerics without quay.io are nothing, got %+v", got)
	}
	if got := find([]byte("quay.io commit " + strings.Repeat("0123456789abcdef", 2) + strings.Repeat("a", 8) + "\n")); got != nil {
		t.Errorf("a git object id is not an OAuth token, got %+v", got)
	}
	// A 40-character auth value near quay.io is base64 the decoder already
	// consumed, not an OAuth token.
	content := config(t, map[string]map[string]string{"quay.io": {"auth": b64("acmeuser:passwordpasswordpass1")}}, nil)
	got := find([]byte(content))
	if len(got) != 1 || got[0].Kind != KindQuayLogin {
		t.Errorf("want the login alone, got %+v", got)
	}
}

func TestFindBasicHeader(t *testing.T) {
	header := `curl -H "Authorization: Basic ` + b64("deploy:hunter2hunter2") + `" https://registry.example.com/v2/_catalog`
	got := find([]byte(header))
	if len(got) != 1 {
		t.Fatalf("want one login, got %+v", got)
	}
	want(t, got, KindRegistryLogin, "registry.example.com/deploy", "hunter2hunter2")
	got = find([]byte("# push to quay.io\nAuthorization: Basic " + b64("acme+ci:pass") + "\n"))
	if len(got) != 1 || got[0].Kind != KindQuayLogin || got[0].Value != "quay.io/acme+ci" {
		t.Errorf("a known registry domain nearby names the host, got %+v", got)
	}
	for _, other := range []string{
		`curl -H "Authorization: Basic ` + b64("user:pass") + `" https://api.example.com/`,
		"Basic " + b64("user:pass") + " https://registry.example.com/v2/",
		"Authorization: Basic notbase64!! https://registry.example.com/v2/",
	} {
		if got := find([]byte(other)); got != nil {
			t.Errorf("%q is not a registry login, got %+v", other, got)
		}
	}
}

func TestKindFor(t *testing.T) {
	cases := map[string]detect.Kind{
		"docker.io": KindHubLogin, "index.docker.io": KindHubLogin, "registry-1.docker.io": KindHubLogin,
		"quay.io": KindQuayLogin, "example.azurecr.io": KindACRLogin, "ghcr.io": KindGHCRLogin,
		"gcr.io": KindGCRLogin, "eu.gcr.io": KindGCRLogin, "europe-west1-docker.pkg.dev": KindGCRLogin,
		"123456789012.dkr.ecr.us-east-1.amazonaws.com": KindECRLogin, "public.ecr.aws": KindECRLogin,
		"harbor.example.com": KindHarborLogin, "registry.example.com:5000": KindRegistryLogin, "localhost:5000": KindRegistryLogin,
	}
	for host, kind := range cases {
		if got := kindFor(host); got != kind {
			t.Errorf("kindFor(%q) = %s, want %s", host, got, kind)
		}
	}
}

func TestKindsAreComplete(t *testing.T) {
	kinds := map[detect.Kind]bool{}
	for _, k := range New().Kinds() {
		kinds[k.Kind] = true
		if k.RevokeNote == "" {
			t.Errorf("%s has no revocation advice", k.Kind)
		}
	}
	for _, k := range []detect.Kind{KindHubLogin, KindQuayLogin, KindACRLogin, KindGHCRLogin, KindGCRLogin, KindECRLogin, KindHarborLogin, KindRegistryLogin, KindHubPAT, KindHubOAT, KindQuayRobot, KindQuayOAuth} {
		if !kinds[k] {
			t.Errorf("%s is not described", k)
		}
	}
}
