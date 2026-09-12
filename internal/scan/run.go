package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/teemow/patty/internal/disk"
	"github.com/teemow/patty/internal/github"
	"github.com/teemow/patty/internal/gitrepo"
	"github.com/teemow/patty/internal/source"
)

// RunOptions configure a run over many targets.
type RunOptions struct {
	Options
	// Cache holds the mirrors of GitHub targets.
	Cache *disk.Cache
	// Keep leaves mirrors in the cache after the scan for faster re-runs.
	Keep bool
	// Auth is used for HTTPS clones; nil for anonymous.
	Auth *gitrepo.Auth
	// GitHub is needed for the activity feed; nil disables it.
	GitHub *github.Client
	// Rewrites fetches commits the activity feed reports as force-pushed or deleted.
	Rewrites bool
	// ActivityPages caps the activity feed pages read per type and repository.
	ActivityPages int
	// Parallel is the number of repositories processed at once.
	Parallel int
	// Progress receives phase messages; may be nil.
	Progress func(target, msg string)
}

// sizeSlack scales GitHub's reported repository size to what a mirror
// occupies on disk: pull request refs and fetched rewritten commits are not
// part of that figure, and a large repository has been measured at three
// times the reported size.
const sizeSlack = 3

// Run scans all targets and calls onResult as each completes. Results are
// returned in target order.
func Run(ctx context.Context, targets []source.Target, opts RunOptions, onResult func(Result)) []Result {
	results := make([]Result, len(targets))
	parallel := max(opts.Parallel, 1)
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, t := range targets {
		if ctx.Err() != nil {
			results[i] = Result{Target: t.Display, Err: ctx.Err(), Error: ctx.Err().Error()}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := runOne(ctx, t, opts)
			if res.Err != nil {
				res.Error = res.Err.Error()
			}
			results[i] = res
			if onResult != nil {
				onResult(res)
			}
		}()
	}
	wg.Wait()
	return results
}

func runOne(ctx context.Context, t source.Target, opts RunOptions) Result {
	progress := func(msg string) {
		if opts.Progress != nil {
			opts.Progress(t.Display, msg)
		}
	}
	if t.Local != "" {
		repo, err := gitrepo.Open(ctx, t.Local)
		if err != nil {
			return Result{Target: t.Display, Err: err}
		}
		progress("scanning")
		return finish(ctx, t.Display, repo, nil, opts.Options)
	}

	estimate := int64(float64(t.Repo.SizeKB)*1024*sizeSlack) + disk.MiB
	path := opts.Cache.RepoPath("github.com", t.Repo.Owner, t.Repo.Name)
	if err := opts.Cache.Admit(path, estimate); err != nil {
		res := Result{Target: t.Display, Err: err}
		res.Skipped = errors.Is(err, disk.ErrBudget)
		return res
	}
	defer opts.Cache.Release(path)
	if !opts.Keep {
		defer removeMirror(path)
	}

	var (
		rewrites []Rewrite
		notes    []string
		fetched  int
		lost     int
	)
	progress(fmt.Sprintf("mirroring (~%s)", disk.FormatSize(estimate)))
	repo, err := gitrepo.Mirror(ctx, t.Repo.CloneURL(), path, opts.Auth)
	if err != nil {
		return Result{Target: t.Display, Err: err}
	}
	disk.Touch(path)
	if free, err := disk.Free(path); err == nil && free < opts.Cache.MinFree {
		notes = append(notes, fmt.Sprintf("mirror is %s, drive is down to %s free (below --min-free %s)", disk.FormatSize(repo.DiskUsage()), disk.FormatSize(free), disk.FormatSize(opts.Cache.MinFree)))
	}

	if opts.Rewrites && opts.GitHub != nil {
		progress("reading activity feed")
		rws, err := opts.GitHub.Rewrites(ctx, t.Repo.Owner, t.Repo.Name, max(opts.ActivityPages, 1))
		if err != nil {
			notes = append(notes, "activity feed unavailable: "+err.Error())
		}
		byBefore := map[string]github.Rewrite{}
		var shas []string
		for _, rw := range rws {
			if _, dup := byBefore[rw.Before]; !dup {
				byBefore[rw.Before] = rw
				shas = append(shas, rw.Before)
			}
		}
		if len(shas) > 0 {
			progress(fmt.Sprintf("fetching %d rewritten commits", len(shas)))
			got, unavailable, err := repo.FetchSHAs(ctx, shas)
			if err != nil {
				return Result{Target: t.Display, Err: err}
			}
			fetched, lost = len(got), len(unavailable)
			for sha, rw := range byBefore {
				rewrites = append(rewrites, Rewrite{SHA: sha, Description: rw.Describe()})
			}
			if lost > 0 {
				notes = append(notes, fmt.Sprintf("%d rewritten commits are no longer served by GitHub", lost))
			}
		}
	}

	progress("scanning")
	res := finish(ctx, t.Display, repo, rewrites, opts.Options)
	res.Stats.Rewrites = fetched
	res.Stats.Unavailable = lost
	res.Stats.Disk = repo.DiskUsage()
	res.Notes = append(res.Notes, notes...)
	return res
}

func finish(ctx context.Context, name string, repo *gitrepo.Repo, rewrites []Rewrite, opts Options) Result {
	res, err := Repo(ctx, name, repo, rewrites, opts)
	if err != nil {
		res.Err = err
		return res
	}
	if n, err := repo.RefCount(ctx); err == nil {
		res.Stats.Refs = n
	}
	return res
}

// removeMirror deletes a mirror and the owner/host directories it leaves
// empty, so a cache dir never fills with empty folders.
func removeMirror(path string) {
	_ = os.RemoveAll(path)
	for dir := filepath.Dir(path); dir != "." && dir != string(filepath.Separator); dir = filepath.Dir(dir) {
		if os.Remove(dir) != nil { // not empty (or not ours): stop
			return
		}
	}
}
