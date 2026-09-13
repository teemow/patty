package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestResolveLocalPaths(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	ctx := context.Background()
	plain := t.TempDir()
	repo := t.TempDir()
	cmd := exec.Command("git", "init", "-q", repo)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	file := filepath.Join(plain, "notes.txt")
	if err := os.WriteFile(file, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := Resolve(ctx, nil, []string{plain, repo, file}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Target{
		{Display: plain, Dir: plain},
		{Display: repo, Local: repo},
		{Display: file, Dir: file},
	}
	if len(targets) != len(want) {
		t.Fatalf("targets: %+v", targets)
	}
	for i, w := range want {
		if targets[i] != w {
			t.Errorf("target %d = %+v, want %+v", i, targets[i], w)
		}
	}
	if !targets[0].Files() || targets[1].Files() || !targets[2].Files() {
		t.Errorf("Files: plain=%v repo=%v file=%v", targets[0].Files(), targets[1].Files(), targets[2].Files())
	}

	// --files adds the working tree to a repository and changes nothing else.
	targets, err = Resolve(ctx, nil, []string{plain, repo}, Options{Files: true})
	if err != nil {
		t.Fatal(err)
	}
	if targets[0] != want[0] || targets[1] != (Target{Display: repo, Local: repo, Dir: repo}) || targets[1].Files() {
		t.Fatalf("with files: %+v", targets)
	}

	// A path that does not exist and is not GitHub-shaped is an error, not a file tree.
	if _, err := Resolve(ctx, nil, []string{filepath.Join(plain, "no such dir")}, Options{}); err == nil {
		t.Fatal("a missing path must not resolve")
	}
}
