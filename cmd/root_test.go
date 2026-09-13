package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect/providers"
	"github.com/teemow/patty/internal/report"
)

func TestExit(t *testing.T) {
	if code, err := exit(nil); code != ExitClean || err != nil {
		t.Errorf("clean: %d, %v", code, err)
	}
	if code, err := exit(exitCode(ExitFindings)); code != ExitFindings || err != nil {
		t.Errorf("findings: %d, %v", code, err)
	}
	if code, err := exit(fmt.Errorf("wrapped: %w", exitCode(ExitError))); code != ExitError || err != nil {
		t.Errorf("a wrapped exit code still counts: %d, %v", code, err)
	}
	boom := errors.New("boom")
	if code, err := exit(boom); code != ExitError || !errors.Is(err, boom) {
		t.Errorf("an error is reported with code %d: %d, %v", ExitError, code, err)
	}
}

// execute runs a fresh root command and returns what it printed and returned.
func execute(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newRootCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func TestRunWithoutTargetsPrintsHelp(t *testing.T) {
	out, _, err := execute(t)
	if err != nil || !strings.Contains(out, "Usage:") || !strings.Contains(out, "--verify") {
		t.Fatalf("help: %v\n%s", err, out)
	}
}

func TestRunRejectsMalformedSizes(t *testing.T) {
	dir := t.TempDir()
	for _, flag := range []string{"--max-disk", "--min-free", "--max-object"} {
		_, _, err := execute(t, flag+"=lots", "--cache-dir", t.TempDir(), dir)
		if err == nil || !strings.HasPrefix(err.Error(), flag+": ") || !strings.Contains(err.Error(), "invalid size") {
			t.Errorf("%s: %v", flag, err)
		}
	}
	if _, _, err := execute(t, "--no-such-flag", dir); err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("unknown flag: %v", err)
	}
}

// hermetic keeps a scan from reading this machine's credentials: an empty
// home, no provider environment variables, and a PATH holding git alone so
// no credential helper is found either.
func hermetic(t *testing.T) {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(git, filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("PATH", bin)
	for _, p := range providers.Default().Providers() {
		src := p.LocalSources()
		for _, name := range append(src.Env, src.EnvFiles...) {
			t.Setenv(name, "")
		}
	}
}

// leakyRepo commits one classic GitHub token into a fresh repository.
func leakyRepo(t *testing.T, tok string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("GITHUB_TOKEN="+tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "."}, {"commit", "-q", "-m", "add env"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=Selma Bouvier", "GIT_AUTHOR_EMAIL=selma@dmv.springfield",
			"GIT_COMMITTER_NAME=Selma Bouvier", "GIT_COMMITTER_EMAIL=selma@dmv.springfield",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestRunExitCodes(t *testing.T) {
	hermetic(t)
	tok := token('p', "RootRootRootRootRootRootRootRo")
	dir := leakyRepo(t, tok)
	cache := t.TempDir()

	out, _, err := execute(t, "--json", "--cache-dir", cache, dir)
	var ec exitCode
	if !errors.As(err, &ec) || int(ec) != ExitFindings {
		t.Fatalf("a finding exits %d: %v", ExitFindings, err)
	}
	var doc report.Output
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Results) != 1 || len(doc.Results[0].Findings) != 1 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	f := doc.Results[0].Findings[0]
	if f.Provider != "GitHub" || strings.Contains(out, tok) || f.Locations[0].Path != ".env" {
		t.Fatalf("finding: %+v", f)
	}

	if out, _, err := execute(t, "--ignore", f.Fingerprint, "--cache-dir", cache, dir); err != nil || !strings.Contains(out, "No credentials found") {
		t.Fatalf("an ignored finding leaves a clean exit: %v\n%s", err, out)
	}

	// A directory that is not a repository is scanned as files: empty, it is clean.
	if out, _, err := execute(t, "--cache-dir", cache, t.TempDir()); err != nil || !strings.Contains(out, "No credentials found in 1 target, 0 files") {
		t.Fatalf("an empty directory is a clean scan: %v\n%s", err, out)
	}

	// A path that exists nowhere is reported as an error, with code 2.
	_, _, err = execute(t, "--cache-dir", cache, filepath.Join(cache, "no such dir"))
	if code, rerr := exit(err); code != ExitError || rerr == nil || !strings.Contains(rerr.Error(), "neither a path") {
		t.Fatalf("a missing path exits %d with an error: %d, %v", ExitError, code, rerr)
	}

	// A local repository stays a repository: the token in an untracked file
	// is not seen without --files, and is seen with it.
	if err := os.WriteFile(filepath.Join(dir, "untracked.env"), []byte("OTHER="+token('o', "UntrackedUntrackedUntrackedUnt")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, _ = execute(t, "--cache-dir", cache, dir)
	if !strings.Contains(out, "1 credential found in 1 repository") {
		t.Fatalf("without --files:\n%s", out)
	}
	out, _, _ = execute(t, "--files", "--cache-dir", cache, dir)
	if !strings.Contains(out, "2 credentials found in 1 repository") || !strings.Contains(out, "untracked.env:1\n") || !strings.Contains(out, "in the working tree") {
		t.Fatalf("with --files:\n%s", out)
	}
}

func TestRunScansDirectoriesAndFilesOnDisk(t *testing.T) {
	hermetic(t)
	tok := token('p', "OnDiskOnDiskOnDiskOnDiskOnDisk")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("GITHUB_TOKEN="+tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if needsGitHub([]string{dir, filepath.Join(dir, ".env")}) || !needsGitHub([]string{dir, "acme/api"}) {
		t.Fatal("existing paths are local, anything else needs GitHub")
	}

	out, _, err := execute(t, "--json", "--cache-dir", t.TempDir(), dir)
	var ec exitCode
	if !errors.As(err, &ec) || int(ec) != ExitFindings {
		t.Fatalf("a finding on disk exits %d: %v", ExitFindings, err)
	}
	var doc report.Output
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Results) != 1 || len(doc.Results[0].Findings) != 1 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	res := doc.Results[0]
	loc := res.Findings[0].Locations[0]
	if !res.Files || doc.Summary.Files != 1 || loc.ObjectType != "file" || loc.Path != ".env" || loc.Line != 1 || loc.Commit != nil || strings.Contains(out, tok) {
		t.Fatalf("result: %+v", res)
	}

	out, _, err = execute(t, "--cache-dir", t.TempDir(), filepath.Join(dir, ".env"))
	if !errors.As(err, &ec) || int(ec) != ExitFindings || !strings.Contains(out, "1 credential found in 1 target, 1 file") || !strings.Contains(out, ".env:1\n") || !strings.Contains(out, "on disk") {
		t.Fatalf("a single file: %v\n%s", err, out)
	}
}
