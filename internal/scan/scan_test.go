package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/github"
	"github.com/teemow/patty/internal/detect/slack"
	"github.com/teemow/patty/internal/disk"
	"github.com/teemow/patty/internal/gitrepo"
	"github.com/teemow/patty/internal/source"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Selma Bouvier", "GIT_AUTHOR_EMAIL=selma@dmv.springfield",
		"GIT_COMMITTER_NAME=Selma Bouvier", "GIT_COMMITTER_EMAIL=selma@dmv.springfield",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func token(prefix, random string) string { return prefix + random + github.Checksum(random) }

// webhook builds a Slack incoming webhook URL at runtime.
func webhook() string {
	return "https://hooks.slack.com/" + "services/" + "T" + "0123ABCD" + "/" + "B" + "0123ABCDEF" + "/" + "AbCdEfGhIjKlMnOpQrStUvWx"
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	orphanRandom  = "OrphanOrphanOrphanOrphanOrphan"
	keptRandom    = "KeptKeptKeptKeptKeptKeptKeptKe"
	messageRandom = "MessageMessageMessageMessageMe"
	ignoredRandom = "IgnoredIgnoredIgnoredIgnoredIg"
)

// fixture: commit 1 leaks a token, is amended away (orphaned); commit 2 leaks
// another token and a Slack webhook in a file plus one token in its commit
// message; a large file holds a token that must be skipped by the size limit.
func fixture(t *testing.T) (dir string, orphanCommit string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, filepath.Join(dir, ".env"), "GITHUB_TOKEN="+token("ghp_", orphanRandom)+"\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "add env")
	orphanCommit = git(t, dir, "rev-parse", "HEAD")

	write(t, filepath.Join(dir, ".env"), "GITHUB_TOKEN=\n")
	write(t, filepath.Join(dir, "deploy.sh"), "#!/bin/sh\n\ncurl -H 'Authorization: token "+token("gho_", keptRandom)+"' https://api.github.com\ncurl -d '{}' "+webhook()+"\n")
	write(t, filepath.Join(dir, "big.log"), strings.Repeat("x", 4096)+token("ghs_", ignoredRandom)+"\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "--amend", "-m", "add deploy script\n\nuses "+token("ghu_", messageRandom)+" for now")
	git(t, dir, "reflog", "expire", "--expire=now", "--all")
	return dir, orphanCommit
}

func TestRepoFindsOrphanedFileAndMessageTokens(t *testing.T) {
	ctx := context.Background()
	dir, orphanCommit := fixture(t)
	repo, err := gitrepo.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	rewrites := []Rewrite{{SHA: orphanCommit, Description: "force-pushed away from main on 2026-09-10"}}
	res, err := Repo(ctx, "fixture", repo, rewrites, Options{Workers: 2, MaxObject: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Skipped != 1 || res.Stats.Orphaned != 1 || res.Stats.Scanned == 0 || res.Stats.Bytes == 0 {
		t.Fatalf("stats: %+v", res.Stats)
	}
	byKind := map[detect.Kind]Finding{}
	for _, f := range res.Findings {
		byKind[f.Kind] = f
	}
	if len(res.Findings) != 4 {
		t.Fatalf("want 4 findings, got %d: %+v", len(res.Findings), res.Findings)
	}

	orphan := byKind[github.KindPAT]
	if orphan.Provider != "GitHub" || orphan.Attribution != "" {
		t.Fatalf("orphan provider: %+v", orphan)
	}
	if len(orphan.Locations) != 1 {
		t.Fatalf("orphan locations: %+v", orphan.Locations)
	}
	loc := orphan.Locations[0]
	if loc.Path != ".env" || loc.Line != 1 || loc.ObjectType != "blob" || !loc.Orphaned || loc.Commit == nil || loc.Commit.SHA != orphanCommit || loc.Rewrite == "" || len(loc.Refs) != 0 {
		t.Fatalf("orphan location: %+v commit=%+v", loc, loc.Commit)
	}
	if orphan.Redacted == orphan.Token || !strings.HasPrefix(orphan.Redacted, "ghp_") || !orphan.ChecksumVerified {
		t.Fatalf("redaction: %+v", orphan)
	}

	kept := byKind[github.KindOAuth]
	loc = kept.Locations[0]
	if loc.Path != "deploy.sh" || loc.Line != 3 || loc.Orphaned || len(loc.Refs) != 1 || loc.Refs[0] != "refs/heads/main" || loc.Commit.Subject != "add deploy script" || loc.Rewrite != "" {
		t.Fatalf("kept location: %+v commit=%+v", loc, loc.Commit)
	}

	msg := byKind[github.KindUserToServer]
	loc = msg.Locations[0]
	if loc.ObjectType != "commit" || loc.Path != "" || loc.Orphaned || loc.Commit == nil || loc.Commit.Subject != "add deploy script" {
		t.Fatalf("message location: %+v commit=%+v", loc, loc.Commit)
	}

	hook := byKind[slack.KindWebhook]
	if hook.Provider != "Slack" || hook.Attribution != "team T0123ABCD, bot B0123ABCDEF" || hook.ChecksumVerified || len(hook.Locations) != 1 || hook.Locations[0].Line != 4 {
		t.Fatalf("webhook finding: %+v", hook)
	}
	if hook.Redacted == hook.Token || !strings.HasPrefix(hook.Redacted, "https://hooks.slack.com/services/T0123ABCD/B0123ABCDEF/") {
		t.Fatalf("webhook redaction: %q", hook.Redacted)
	}

	// Ignoring by fingerprint drops the finding entirely.
	res, err = Repo(ctx, "fixture", repo, nil, Options{Workers: 1, Ignore: map[string]bool{kept.Fingerprint: true}})
	if err != nil || len(res.Findings) != 4 { // no size limit: the large object's token appears, the ignored one disappears
		t.Fatalf("ignore: %d findings, %v", len(res.Findings), err)
	}
	for _, f := range res.Findings {
		if f.Fingerprint == kept.Fingerprint {
			t.Fatal("ignored fingerprint must not be reported")
		}
	}
}

func TestRunLocalTargetAndSummary(t *testing.T) {
	dir, _ := fixture(t)
	var seen []string
	results := Run(context.Background(), []source.Target{{Display: "local", Local: dir}, {Display: "missing", Local: t.TempDir()}},
		RunOptions{Options: Options{Workers: 1}, Cache: &disk.Cache{Dir: t.TempDir(), MaxBytes: disk.GiB, MinFree: 0}, Parallel: 2},
		func(r Result) { seen = append(seen, r.Target) })
	if len(results) != 2 || len(seen) != 2 {
		t.Fatalf("results=%d seen=%d", len(results), len(seen))
	}
	if results[0].Err != nil || len(results[0].Findings) != 5 || results[0].Stats.Refs != 1 {
		t.Fatalf("local: %+v", results[0])
	}
	if results[1].Err == nil || results[1].Error == "" {
		t.Fatalf("missing: %+v", results[1])
	}
	s := Summarize(results)
	if s.Repos != 2 || s.Failed != 1 || s.Tokens != 5 || s.Active != 0 {
		t.Fatalf("summary: %+v", s)
	}
	if d := Describe(results[1]); !strings.HasPrefix(d, "failed: ") {
		t.Fatalf("Describe failed = %q", d)
	}
	if d := Describe(results[0]); !strings.Contains(d, "objects") || !strings.Contains(d, "1 refs") || !strings.Contains(d, "1 orphaned") {
		t.Fatalf("Describe ok = %q", d)
	}
}

func TestRemoveMirrorStopsAtCacheRoot(t *testing.T) {
	root := t.TempDir()
	mirror := filepath.Join(root, "github.com", "acme", "app.git")
	sibling := filepath.Join(root, "github.com", "acme", "lib.git")
	for _, d := range []string{mirror, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	removeMirror(mirror, root)
	if _, err := os.Stat(mirror); !os.IsNotExist(err) {
		t.Fatal("mirror must be removed")
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatal("sibling mirror must survive")
	}
	removeMirror(sibling, root)
	if _, err := os.Stat(filepath.Join(root, "github.com")); !os.IsNotExist(err) {
		t.Fatal("empty host directory must be removed")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("cache root must survive")
	}
}
