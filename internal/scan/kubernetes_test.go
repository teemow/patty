package scan

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/kubernetes"
	"github.com/teemow/patty/internal/gitrepo"
)

const secretRandom = "SecretSecretSecretSecretSecret"

// secretManifest wraps a GitHub token in a Secret manifest, base64 under
// data, the way a committed Secret carries it.
func secretManifest(token string) string {
	return "apiVersion: v1\nkind: " + "Secret\nmetadata:\n  name: ci-credentials\n  namespace: build\ntype: Opaque\ndata:\n  GITHUB_TOKEN: " + base64.StdEncoding.EncodeToString([]byte(token)) + "\n  OTHER: " + base64.StdEncoding.EncodeToString([]byte("not a token")) + "\n"
}

func TestRepoFindsTokensInsideSecretManifests(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	tok := token("ghp_", secretRandom)
	write(t, filepath.Join(dir, "secret.yaml"), secretManifest(tok))
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "add ci credentials")
	repo, err := gitrepo.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Repo(ctx, "fixture", repo, Remote{}, Options{Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("want the GitHub token and the Secret manifest, got %+v", res.Findings)
	}
	// The verifiable token comes first, the opaque manifest after it.
	gh, manifest := res.Findings[0], res.Findings[1]
	if gh.Kind != github.KindPAT || gh.Token != tok || gh.Attribution != "in Secret build/ci-credentials, key GITHUB_TOKEN" || gh.Opaque {
		t.Fatalf("github finding: %+v", gh)
	}
	if len(gh.Locations) != 1 || gh.Locations[0].Path != "secret.yaml" || gh.Locations[0].Line != 8 {
		t.Fatalf("github location: %+v", gh.Locations)
	}
	if manifest.Kind != kubernetes.KindSecretManifest || manifest.Token != "build/ci-credentials" || manifest.Redacted != "build/ci-credentials" || !manifest.Opaque || manifest.Provider != "Kubernetes" {
		t.Fatalf("manifest finding: %+v", manifest)
	}
	if manifest.Attribution != "keys GITHUB_TOKEN, OTHER" || manifest.Locations[0].Line != 2 {
		t.Fatalf("manifest attribution: %+v", manifest)
	}
	if strings.Contains(manifest.Attribution, "not a token") {
		t.Fatal("values must never appear in the manifest finding")
	}

	// --ignore takes the kind as well as a fingerprint.
	res, err = Repo(ctx, "fixture", repo, Remote{}, Options{Workers: 1, Ignore: map[string]bool{string(kubernetes.KindSecretManifest): true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Kind != github.KindPAT {
		t.Fatalf("ignored kind: %+v", res.Findings)
	}
}

func TestSortFindingsPutsOpaqueAfterVerifiable(t *testing.T) {
	active := &detect.Verification{Status: detect.StatusActive}
	revoked := &detect.Verification{Status: detect.StatusRevoked}
	unverifiable := &detect.Verification{Status: detect.StatusUnverifiable}
	fs := []Finding{
		{Kind: "a-revoked", Fingerprint: "1", Verification: revoked},
		{Kind: "a-opaque", Fingerprint: "2", Opaque: true},
		{Kind: "a-opaque-checked", Fingerprint: "3", Opaque: true, Verification: unverifiable},
		{Kind: "z-unverified", Fingerprint: "4"},
		{Kind: "a-active", Fingerprint: "5", Verification: active},
	}
	SortFindings(fs)
	var order []string
	for _, f := range fs {
		order = append(order, f.Fingerprint)
	}
	if got := strings.Join(order, ""); got != "54231" {
		t.Fatalf("order %s: active, unverified, opaque, revoked", got)
	}
}
