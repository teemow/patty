// Package gitrepo drives git plumbing for a repository patty scans. It
// works on the object database directly (bare mirrors or a working tree's
// .git) so that objects no ref points at anymore -- rewritten, force-pushed
// or otherwise orphaned commits -- are scanned like everything else.
package gitrepo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// tokenEnv is the environment variable the credential helper reads the
// HTTPS token from. Passing it through the environment keeps the token out
// of the process list, where a -c http.extraHeader would expose it.
const tokenEnv = "PATTY_GIT_TOKEN"

// Auth carries the token used for HTTPS access to a remote.
type Auth struct {
	Token string
}

// Repo is an opened repository.
type Repo struct {
	// GitDir is the absolute path of the git directory.
	GitDir string
	auth   *Auth
}

// Open opens the repository at path (a working tree or a bare/git directory).
func Open(ctx context.Context, path string) (*Repo, error) {
	out, err := output(ctx, nil, "-C", path, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return nil, fmt.Errorf("%s is not a git repository: %w", path, err)
	}
	return &Repo{GitDir: strings.TrimSpace(string(out))}, nil
}

// Mirror clones url as a bare mirror into dir, or refreshes the mirror if
// dir already holds one. A mirror carries every ref the server advertises
// (heads, tags and on GitHub also refs/pull/*), not just the branches.
func Mirror(ctx context.Context, url, dir string, auth *Auth) (*Repo, error) {
	r := &Repo{GitDir: dir, auth: auth}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil {
		if _, err := r.run(ctx, "fetch", "--quiet", "--prune", "--prune-tags", "origin"); err != nil {
			return nil, fmt.Errorf("refreshing mirror: %w", err)
		}
		return r, nil
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, err
	}
	if _, err := output(ctx, auth, "clone", "--quiet", "--mirror", url, dir); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("cloning: %w", err)
	}
	return r, nil
}

// Object is one entry of the object database.
type Object struct {
	SHA  string
	Type string
	Size int64
}

const batchFormat = "%(objectname) %(objecttype) %(objectsize)"

// Objects lists every object in the database, reachable or not.
func (r *Repo) Objects(ctx context.Context) ([]Object, error) {
	out, err := r.run(ctx, "cat-file", "--batch-all-objects", "--unordered", "--batch-check="+batchFormat)
	if err != nil {
		return nil, fmt.Errorf("listing objects: %w", err)
	}
	var objs []Object
	for line := range bytes.Lines(out) {
		obj, ok := parseHeader(bytes.TrimRight(line, "\n"))
		if ok {
			objs = append(objs, obj)
		}
	}
	return objs, nil
}

func parseHeader(line []byte) (Object, bool) {
	fields := bytes.Fields(line)
	if len(fields) != 3 {
		return Object{}, false
	}
	var size int64
	for _, c := range fields[2] {
		if c < '0' || c > '9' {
			return Object{}, false
		}
		size = size*10 + int64(c-'0')
	}
	return Object{SHA: string(fields[0]), Type: string(fields[1]), Size: size}, true
}

// ReadObjects streams the content of the given objects through one
// `git cat-file --batch` process and calls fn for each. The content slice
// is reused between calls; fn must copy what it wants to keep.
func (r *Repo) ReadObjects(ctx context.Context, shas []string, fn func(Object, []byte) error) error {
	if len(shas) == 0 {
		return nil
	}
	cmd := r.cmd(ctx, "cat-file", "--batch="+batchFormat)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	writeErr := make(chan error, 1)
	go func() {
		defer func() { _ = stdin.Close() }()
		w := newBufWriter(stdin)
		for _, sha := range shas {
			if _, err := w.WriteString(sha + "\n"); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- w.Flush()
	}()

	rd := newBufReader(stdout)
	var buf []byte
	var readErr error
	for range shas {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			readErr = fmt.Errorf("reading object header: %w", err)
			break
		}
		line = bytes.TrimRight(line, "\n")
		if bytes.HasSuffix(line, []byte(" missing")) {
			continue
		}
		obj, ok := parseHeader(line)
		if !ok {
			readErr = fmt.Errorf("unexpected cat-file header %q", line)
			break
		}
		if int64(cap(buf)) < obj.Size {
			buf = make([]byte, obj.Size)
		}
		buf = buf[:obj.Size]
		if _, err := readFull(rd, buf); err != nil {
			readErr = fmt.Errorf("reading object %s: %w", obj.SHA, err)
			break
		}
		if _, err := rd.Discard(1); err != nil { // trailing newline
			readErr = err
			break
		}
		if err := fn(obj, buf); err != nil {
			readErr = err
			break
		}
	}
	if readErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return readErr
	}
	if err := <-writeErr; err != nil {
		return err
	}
	if waitErr != nil {
		return fmt.Errorf("git cat-file: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ReachableCommits returns the set of commits reachable from any ref or
// reflog entry.
func (r *Repo) ReachableCommits(ctx context.Context) (map[string]bool, error) {
	out, err := r.run(ctx, "rev-list", "--all", "--reflog")
	if err != nil {
		return nil, fmt.Errorf("listing reachable commits: %w", err)
	}
	set := make(map[string]bool)
	for line := range bytes.Lines(out) {
		if sha := bytes.TrimSpace(line); len(sha) > 0 {
			set[string(sha)] = true
		}
	}
	return set, nil
}

// ObjectPaths maps trees and blobs to a path they were seen at. With no
// roots it walks everything reachable from refs and reflogs; with roots it
// walks from those commits only and excludes everything reachable from
// refs, which yields the objects that exist solely in orphaned history.
func (r *Repo) ObjectPaths(ctx context.Context, roots []string) (map[string]string, error) {
	var (
		out []byte
		err error
	)
	if len(roots) == 0 {
		out, err = r.run(ctx, "rev-list", "--objects", "--all", "--reflog")
	} else {
		out, err = r.runInput(ctx, strings.Join(roots, "\n")+"\n--not\n--all\n", "rev-list", "--objects", "--stdin")
	}
	if err != nil {
		return nil, fmt.Errorf("mapping objects to paths: %w", err)
	}
	paths := make(map[string]string)
	for line := range bytes.Lines(out) {
		line = bytes.TrimRight(line, "\n")
		if sha, path, ok := bytes.Cut(line, []byte{' '}); ok {
			paths[string(sha)] = string(path)
		}
	}
	return paths, nil
}

// Commit describes a commit for a report.
type Commit struct {
	SHA     string `json:"sha"`
	Author  string `json:"author"`
	Email   string `json:"email"`
	Date    string `json:"date"`
	Subject string `json:"subject"`
}

const commitFormat = "%H%x1f%aN%x1f%aE%x1f%aI%x1f%s"

// IntroducingCommit returns the oldest commit that added the given object,
// searched from all refs and reflogs, or from roots when given.
func (r *Repo) IntroducingCommit(ctx context.Context, object string, roots []string) (*Commit, error) {
	var (
		out []byte
		err error
	)
	if len(roots) == 0 {
		out, err = r.run(ctx, "log", "--all", "--reflog", "--find-object="+object, "--format="+commitFormat)
	} else {
		out, err = r.runInput(ctx, strings.Join(roots, "\n")+"\n", "log", "--stdin", "--find-object="+object, "--format="+commitFormat)
	}
	if err != nil {
		return nil, fmt.Errorf("finding commit introducing %s: %w", object, err)
	}
	lines := bytes.Split(bytes.TrimSpace(out), []byte{'\n'})
	last := lines[len(lines)-1]
	if len(last) == 0 {
		return nil, nil
	}
	return parseCommit(last), nil
}

// Commit returns the metadata of one commit.
func (r *Repo) Commit(ctx context.Context, sha string) (*Commit, error) {
	out, err := r.run(ctx, "log", "-1", "--format="+commitFormat, sha)
	if err != nil {
		return nil, fmt.Errorf("reading commit %s: %w", sha, err)
	}
	return parseCommit(bytes.TrimSpace(out)), nil
}

func parseCommit(line []byte) *Commit {
	f := strings.SplitN(string(line), "\x1f", 5)
	for len(f) < 5 {
		f = append(f, "")
	}
	return &Commit{SHA: f[0], Author: f[1], Email: f[2], Date: f[3], Subject: f[4]}
}

// RefsContaining lists the refs whose history contains the commit.
func (r *Repo) RefsContaining(ctx context.Context, commit string) ([]string, error) {
	out, err := r.run(ctx, "for-each-ref", "--contains", commit, "--format=%(refname)")
	if err != nil {
		return nil, fmt.Errorf("listing refs containing %s: %w", commit, err)
	}
	var refs []string
	for line := range bytes.Lines(out) {
		if ref := bytes.TrimSpace(line); len(ref) > 0 {
			refs = append(refs, string(ref))
		}
	}
	return refs, nil
}

// RefCount returns the number of refs in the repository.
func (r *Repo) RefCount(ctx context.Context) (int, error) {
	out, err := r.run(ctx, "for-each-ref", "--format=x")
	if err != nil {
		return 0, err
	}
	return bytes.Count(out, []byte{'\n'}), nil
}

// IsAncestor reports whether a is an ancestor of b.
func (r *Repo) IsAncestor(ctx context.Context, a, b string) bool {
	_, err := r.run(ctx, "merge-base", "--is-ancestor", a, b)
	return err == nil
}

// Has reports which of the given objects exist in the database.
func (r *Repo) Has(ctx context.Context, shas []string) (map[string]bool, error) {
	if len(shas) == 0 {
		return map[string]bool{}, nil
	}
	out, err := r.runInput(ctx, strings.Join(shas, "\n")+"\n", "cat-file", "--batch-check="+batchFormat)
	if err != nil {
		return nil, fmt.Errorf("checking objects: %w", err)
	}
	has := make(map[string]bool, len(shas))
	for line := range bytes.Lines(out) {
		if obj, ok := parseHeader(bytes.TrimRight(line, "\n")); ok {
			has[obj.SHA] = true
		}
	}
	return has, nil
}

// fetchParallel bounds the concurrent single-SHA fetches used when a batch
// fetch fails because the server no longer has one of the commits.
const fetchParallel = 8

// FetchSHAs fetches the given commits from origin by SHA -- GitHub serves
// any object it still holds, including commits that were force-pushed away.
// Objects already present are skipped. It returns the SHAs fetched and the
// ones the server no longer has.
func (r *Repo) FetchSHAs(ctx context.Context, shas []string) (fetched, unavailable []string, err error) {
	has, err := r.Has(ctx, shas)
	if err != nil {
		return nil, nil, err
	}
	var missing []string
	for _, sha := range shas {
		if !has[sha] {
			missing = append(missing, sha)
		}
	}
	const chunk = 64
	var retry []string
	for start := 0; start < len(missing); start += chunk {
		batch := missing[start:min(start+chunk, len(missing))]
		if err := r.fetch(ctx, batch...); err == nil {
			fetched = append(fetched, batch...)
		} else {
			retry = append(retry, batch...)
		}
	}
	if len(retry) == 0 {
		return fetched, nil, ctx.Err()
	}

	// One object the server has pruned fails the whole batch and git does
	// not say which; fetch the rest one by one, several at a time. Without
	// ref updates concurrent fetches into one object database are safe.
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, fetchParallel)
	)
	for _, sha := range retry {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			err := r.fetch(ctx, sha)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				unavailable = append(unavailable, sha)
			} else {
				fetched = append(fetched, sha)
			}
		}()
	}
	wg.Wait()
	return fetched, unavailable, ctx.Err()
}

func (r *Repo) fetch(ctx context.Context, shas ...string) error {
	_, err := r.run(ctx, append([]string{"fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "origin"}, shas...)...)
	return err
}

// DiskUsage returns the size of the git directory in bytes.
func (r *Repo) DiskUsage() int64 {
	return DirSize(r.GitDir)
}

// DirSize sums the size of all regular files under dir.
func DirSize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func (r *Repo) cmd(ctx context.Context, args ...string) *exec.Cmd {
	return gitCmd(ctx, r.auth, append([]string{"--git-dir", r.GitDir}, args...)...)
}

func (r *Repo) run(ctx context.Context, args ...string) ([]byte, error) {
	return runCmd(r.cmd(ctx, args...), nil)
}

func (r *Repo) runInput(ctx context.Context, input string, args ...string) ([]byte, error) {
	return runCmd(r.cmd(ctx, args...), strings.NewReader(input))
}

func output(ctx context.Context, auth *Auth, args ...string) ([]byte, error) {
	return runCmd(gitCmd(ctx, auth, args...), nil)
}

func gitCmd(ctx context.Context, auth *Auth, args ...string) *exec.Cmd {
	base := []string{"-c", "gc.auto=0", "-c", "core.quotePath=false"}
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if auth != nil && auth.Token != "" {
		base = append(base,
			"-c", "credential.helper=",
			"-c", `credential.helper=!f() { echo username=x-access-token; echo "password=$`+tokenEnv+`"; }; f`,
		)
		env = append(env, tokenEnv+"="+auth.Token)
	}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Env = env
	return cmd
}

func runCmd(cmd *exec.Cmd, stdin *strings.Reader) ([]byte, error) {
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		var exit *exec.ExitError
		if errors.As(err, &exit) && msg != "" {
			return nil, fmt.Errorf("git %s: %s", cmd.Args[len(cmd.Args)-min(len(cmd.Args), 2)], firstLine(msg))
		}
		return nil, fmt.Errorf("git: %w", err)
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
