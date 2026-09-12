package gitrepo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Patty Bouvier", "GIT_AUTHOR_EMAIL=patty@dmv.springfield",
		"GIT_COMMITTER_NAME=Patty Bouvier", "GIT_COMMITTER_EMAIL=patty@dmv.springfield",
		"GIT_AUTHOR_DATE=2026-01-02T03:04:05Z", "GIT_COMMITTER_DATE=2026-01-02T03:04:05Z",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// fixture builds a repository whose first commit was amended away, leaving
// an orphaned commit (and blob) in the object database.
func fixture(t *testing.T) (dir, orphanCommit, orphanBlob, keptBlob string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, filepath.Join(dir, "config.env"), "TOKEN=orphaned-secret\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "add config")
	orphanCommit = git(t, dir, "rev-parse", "HEAD")
	orphanBlob = git(t, dir, "rev-parse", "HEAD:config.env")
	write(t, filepath.Join(dir, "config.env"), "TOKEN=redacted\n")
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "--amend", "-m", "add config (clean)")
	keptBlob = git(t, dir, "rev-parse", "HEAD:config.env")
	// Drop the reflog so the amended-away commit is truly unreachable.
	git(t, dir, "reflog", "expire", "--expire=now", "--all")
	return dir, orphanCommit, orphanBlob, keptBlob
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOrphanedObjectsAreVisibleAndAttributable(t *testing.T) {
	ctx := context.Background()
	dir, orphanCommit, orphanBlob, keptBlob := fixture(t)

	repo, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if repo.GitDir != filepath.Join(dir, ".git") {
		t.Fatalf("GitDir = %q", repo.GitDir)
	}

	objs, err := repo.Objects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, o := range objs {
		types[o.SHA] = o.Type
	}
	if types[orphanBlob] != "blob" || types[keptBlob] != "blob" || types[orphanCommit] != "commit" {
		t.Fatalf("orphaned objects missing from listing: %v", types)
	}

	var contents []string
	err = repo.ReadObjects(ctx, []string{orphanBlob, "0000000000000000000000000000000000000000", keptBlob}, func(o Object, b []byte) error {
		if int64(len(b)) != o.Size {
			t.Fatalf("size mismatch for %s", o.SHA)
		}
		contents = append(contents, string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 2 || contents[0] != "TOKEN=orphaned-secret\n" || contents[1] != "TOKEN=redacted\n" {
		t.Fatalf("unexpected contents %q", contents)
	}

	reachable, err := repo.ReachableCommits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[orphanCommit] || len(reachable) != 1 {
		t.Fatalf("orphan must not be reachable: %v", reachable)
	}

	paths, err := repo.ObjectPaths(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if paths[keptBlob] != "config.env" || paths[orphanBlob] != "" {
		t.Fatalf("reachable paths wrong: %v", paths)
	}
	orphanPaths, err := repo.ObjectPaths(ctx, []string{orphanCommit})
	if err != nil {
		t.Fatal(err)
	}
	if orphanPaths[orphanBlob] != "config.env" || orphanPaths[keptBlob] != "" {
		t.Fatalf("orphan paths wrong: %v", orphanPaths)
	}

	c, err := repo.IntroducingCommit(ctx, orphanBlob, []string{orphanCommit})
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.SHA != orphanCommit || c.Author != "Patty Bouvier" || c.Subject != "add config" || !strings.HasPrefix(c.Date, "2026-01-02") {
		t.Fatalf("unexpected commit %+v", c)
	}
	if c, err := repo.IntroducingCommit(ctx, orphanBlob, nil); err != nil || c != nil {
		t.Fatalf("orphan blob must not be found from refs: %+v %v", c, err)
	}
	kept, err := repo.IntroducingCommit(ctx, keptBlob, nil)
	if err != nil || kept == nil || kept.Subject != "add config (clean)" {
		t.Fatalf("kept blob: %+v %v", kept, err)
	}

	refs, err := repo.RefsContaining(ctx, orphanCommit)
	if err != nil || len(refs) != 0 {
		t.Fatalf("orphan must be contained by no ref: %v %v", refs, err)
	}
	refs, err = repo.RefsContaining(ctx, kept.SHA)
	if err != nil || len(refs) != 1 || refs[0] != "refs/heads/main" {
		t.Fatalf("kept commit refs: %v %v", refs, err)
	}
	if n, err := repo.RefCount(ctx); err != nil || n != 1 {
		t.Fatalf("RefCount = %d, %v", n, err)
	}
	if !repo.IsAncestor(ctx, kept.SHA, kept.SHA) || repo.IsAncestor(ctx, orphanCommit, kept.SHA) {
		t.Fatal("IsAncestor wrong")
	}
	has, err := repo.Has(ctx, []string{orphanBlob, "0000000000000000000000000000000000000000"})
	if err != nil || !has[orphanBlob] || len(has) != 1 {
		t.Fatalf("Has = %v, %v", has, err)
	}
	if repo.DiskUsage() <= 0 {
		t.Fatal("DiskUsage must be positive")
	}
}

func TestMirrorAndFetchSHAs(t *testing.T) {
	ctx := context.Background()
	src, orphanCommit, orphanBlob, _ := fixture(t)

	mirror := filepath.Join(t.TempDir(), "cache", "fixture.git")
	repo, err := Mirror(ctx, "file://"+src, mirror, nil)
	if err != nil {
		t.Fatal(err)
	}
	if has, _ := repo.Has(ctx, []string{orphanBlob}); has[orphanBlob] {
		t.Fatal("a fresh mirror must not contain the orphaned blob")
	}

	// Local transports refuse SHAs that are not reachable, so make the orphan
	// reachable on the source through a hidden ref -- GitHub serves any SHA it
	// holds, which is what FetchSHAs relies on in production.
	git(t, src, "update-ref", "refs/hidden/orphan", orphanCommit)
	git(t, src, "config", "uploadpack.allowAnySHA1InWant", "true")
	fetched, unavailable, err := repo.FetchSHAs(ctx, []string{orphanCommit, "1111111111111111111111111111111111111111"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 1 || fetched[0] != orphanCommit || len(unavailable) != 1 {
		t.Fatalf("fetched=%v unavailable=%v", fetched, unavailable)
	}
	if has, _ := repo.Has(ctx, []string{orphanBlob}); !has[orphanBlob] {
		t.Fatal("orphaned blob must be present after fetching its commit")
	}
	// Already present: nothing to fetch, nothing unavailable.
	fetched, unavailable, err = repo.FetchSHAs(ctx, []string{orphanCommit})
	if err != nil || len(fetched) != 0 || len(unavailable) != 0 {
		t.Fatalf("second fetch: %v %v %v", fetched, unavailable, err)
	}

	// Refreshing an existing mirror takes the fetch path.
	if _, err := Mirror(ctx, "file://"+src, mirror, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsNonRepo(t *testing.T) {
	if _, err := Open(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected error")
	}
}
