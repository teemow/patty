package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/sops"
	"github.com/teemow/patty/internal/source"
)

const (
	nestedRandom  = "NestedNestedNestedNestedNested"
	linkedRandom  = "LinkedLinkedLinkedLinkedLinked"
	gitdirRandom  = "GitdirGitdirGitdirGitdirGitdir"
	largeRandom   = "LargeLargeLargeLargeLargeLarge"
	trackedRandom = "TrackedTrackedTrackedTrackedTr"
)

// tree builds a directory that is not a repository: a token in a nested
// file, a token in a file that is too large, a token behind a symbolic
// link that must not be followed, and a token inside a .git directory that
// must be skipped.
func tree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	outside := t.TempDir()
	for _, dir := range []string{"config/env", ".git/objects", "linked"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(root, "config", "env", ".env"), "export GITHUB_TOKEN="+token("ghp_", nestedRandom)+"\n")
	write(t, filepath.Join(root, "big.log"), strings.Repeat("x", 4096)+token("ghp_", largeRandom)+"\n")
	write(t, filepath.Join(root, ".git", "objects", "packed"), token("ghp_", gitdirRandom)+"\n")
	write(t, filepath.Join(outside, "secret.txt"), token("ghp_", linkedRandom)+"\n")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked", "dir")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "README.md"), "nothing to see\n")
	return root
}

func TestDirWalksFilesAndSkipsWhatItMust(t *testing.T) {
	ctx := context.Background()
	root := tree(t)
	res, err := Dir(ctx, "downloads", root, Options{Providers: defaultProviders, Workers: 2, MaxObject: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Files || res.Stats.Objects != 3 || res.Stats.Scanned != 2 || res.Stats.Skipped != 1 || res.Stats.Bytes == 0 {
		t.Fatalf("stats: files=%v %+v", res.Files, res.Stats)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want the nested token alone, got %+v", res.Findings)
	}
	f := res.Findings[0]
	want := []Location{{Repo: "downloads", Path: "config/env/.env", Line: 1, ObjectType: "file"}}
	if f.Kind != github.KindPAT || !f.ChecksumVerified || f.Occurrences != 1 || !reflect.DeepEqual(f.Locations, want) {
		t.Fatalf("finding: %+v", f)
	}
	out, err := json.Marshal(res)
	if err != nil || strings.Contains(string(out), nestedRandom) || !strings.Contains(string(out), `"object_type":"file"`) || !strings.Contains(string(out), `"path":"config/env/.env"`) || !strings.Contains(string(out), `"files":true`) {
		t.Fatalf("json: %v\n%s", err, out)
	}

	// Without a size limit the large file is scanned too; ignoring by kind drops everything.
	res, err = Dir(ctx, "downloads", root, Options{Providers: defaultProviders, Workers: 1})
	if err != nil || len(res.Findings) != 2 || res.Stats.Skipped != 0 {
		t.Fatalf("no limit: %d findings, %v", len(res.Findings), err)
	}
	res, err = Dir(ctx, "downloads", root, Options{Providers: defaultProviders, Ignore: map[string]bool{string(github.KindPAT): true}})
	if err != nil || len(res.Findings) != 0 {
		t.Fatalf("ignored kind: %+v, %v", res.Findings, err)
	}
	if d := Describe(res); !strings.Contains(d, "3 files") {
		t.Fatalf("Describe = %q", d)
	}
}

func TestDirScansASingleFile(t *testing.T) {
	root := tree(t)
	file := filepath.Join(root, "config", "env", ".env")
	res, err := Dir(context.Background(), file, file, Options{Providers: defaultProviders})
	if err != nil || len(res.Findings) != 1 || res.Stats.Objects != 1 {
		t.Fatalf("%+v, %v", res, err)
	}
	if loc := res.Findings[0].Locations[0]; loc.Path != ".env" || loc.Repo != file {
		t.Fatalf("location: %+v", loc)
	}
}

func TestDirCorrelatesIdentitiesWithSopsRecipients(t *testing.T) {
	dir, id := sopsFixture(t)
	res, err := Dir(context.Background(), "fixture", dir, Options{Providers: defaultProviders, Workers: 4, Verify: true})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("%d findings, %v", len(res.Findings), err)
	}
	f := res.Findings[0]
	if f.Kind != sops.KindAge || f.Attribution != "recipient "+id.Recipient().String() || !f.Unverifiable() {
		t.Fatalf("finding: %+v", f)
	}
	if len(f.Locations) != 1 || f.Locations[0].Path != "keys.txt" || f.Locations[0].Line != 3 || f.Locations[0].Commit != nil {
		t.Fatalf("locations: %+v", f.Locations)
	}
	want := []Unlock{{Repo: "fixture", Path: ".sops.yaml"}, {Repo: "fixture", Path: "secrets/db.sops.yaml"}}
	if !reflect.DeepEqual(f.Unlocks, want) {
		t.Fatalf("unlocks %+v, want %+v", f.Unlocks, want)
	}
}

func TestRunMergesRepositoryAndWorkingTree(t *testing.T) {
	dir := t.TempDir()
	tracked := token("ghp_", trackedRandom)
	git(t, dir, "init", "-q", "-b", "main")
	write(t, filepath.Join(dir, "deploy.sh"), "curl -H 'Authorization: token "+tracked+"'\n")
	write(t, filepath.Join(dir, ".gitignore"), ".env\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "add deploy script")
	// The same token once more in an ignored file, plus one that was never committed.
	write(t, filepath.Join(dir, ".env"), "TOKEN="+tracked+"\nOTHER="+token("ghp_", nestedRandom)+"\n")

	opts := RunOptions{Options: Options{Providers: defaultProviders, Workers: 1}, Parallel: 1}
	results := Run(context.Background(), []source.Target{{Display: "repo", Local: dir}}, opts, nil)
	if len(results) != 1 || results[0].Err != nil || len(results[0].Findings) != 1 || results[0].Files {
		t.Fatalf("object database alone: %+v", results[0])
	}

	results = Run(context.Background(), []source.Target{{Display: "repo", Local: dir, Dir: dir}}, opts, nil)
	res := results[0]
	if res.Err != nil || res.Files || len(res.Findings) != 2 || res.Stats.Refs != 1 || res.Stats.Scanned < 5 {
		t.Fatalf("merged: %+v", res)
	}
	byFP := map[string]Finding{}
	for _, f := range res.Findings {
		byFP[f.Token] = f
	}
	both := byFP[tracked]
	if len(both.Locations) != 3 || both.Occurrences != 3 {
		t.Fatalf("a token in history and on disk is one finding with every location: %+v", both)
	}
	// History first, then the working tree: the committed file as checked out, and the ignored one.
	want := []struct{ objectType, path string }{{"blob", "deploy.sh"}, {"file", ".env"}, {"file", "deploy.sh"}}
	for i, w := range want {
		l := both.Locations[i]
		if l.ObjectType != w.objectType || l.Path != w.path || (l.Commit == nil) != (w.objectType == "file") {
			t.Fatalf("location %d: %+v", i, l)
		}
	}
	only := byFP[token("ghp_", nestedRandom)]
	if len(only.Locations) != 1 || only.Locations[0].ObjectType != "file" || only.Locations[0].Line != 2 {
		t.Fatalf("untracked token: %+v", only)
	}
	if s := Summarize(results); s.Repos != 1 || s.Files != 0 || s.Tokens != 2 {
		t.Fatalf("summary: %+v", s)
	}
}

func TestRunScansADirectoryThatIsNoRepository(t *testing.T) {
	root := tree(t)
	results := Run(context.Background(), []source.Target{{Display: "downloads", Dir: root}},
		RunOptions{Options: Options{Providers: defaultProviders, MaxObject: 2048}, Parallel: 1}, nil)
	if len(results) != 1 || results[0].Err != nil || !results[0].Files || len(results[0].Findings) != 1 {
		t.Fatalf("%+v", results[0])
	}
	if s := Summarize(results); s.Repos != 1 || s.Files != 1 {
		t.Fatalf("summary: %+v", s)
	}
}
