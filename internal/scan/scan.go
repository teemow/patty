// Package scan runs the detector over every object of a repository and
// attributes what it finds to commits, paths and refs.
package scan

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/gitrepo"
)

// Options tune a repository scan.
type Options struct {
	// Workers is the number of parallel `git cat-file` readers.
	Workers int
	// MaxObject skips objects larger than this many bytes.
	MaxObject int64
	// Ignore holds token fingerprints to leave out of the results.
	Ignore map[string]bool
	// Verifier, when set, checks each token against the GitHub API.
	Verifier *detect.Verifier
}

func (o Options) workers() int {
	if o.Workers > 0 {
		return o.Workers
	}
	return runtime.NumCPU()
}

// Rewrite names a commit that was fetched by SHA because a server-side ref
// update (force push, branch deletion) had made it unreachable.
type Rewrite struct {
	SHA         string
	Description string
}

// Location is one place a token was found.
type Location struct {
	Repo       string          `json:"repo"`
	Object     string          `json:"object"`
	ObjectType string          `json:"object_type"`
	Path       string          `json:"path,omitempty"`
	Line       int             `json:"line"`
	Commit     *gitrepo.Commit `json:"commit,omitempty"`
	// Refs contains the refs whose history includes the commit.
	Refs []string `json:"refs,omitempty"`
	// Orphaned is true when no ref reaches the commit anymore.
	Orphaned bool `json:"orphaned"`
	// Rewrite explains how the commit went unreachable on the server, when known.
	Rewrite string `json:"rewrite,omitempty"`
}

// Finding is one distinct token and everywhere it appears.
type Finding struct {
	Kind             detect.Kind          `json:"kind"`
	Fingerprint      string               `json:"fingerprint"`
	Token            string               `json:"-"`
	Redacted         string               `json:"token"`
	ChecksumVerified bool                 `json:"checksum_verified"`
	Verification     *detect.Verification `json:"verification,omitempty"`
	// Revocation records what happened when patty asked GitHub to revoke the token.
	Revocation Revocation `json:"revocation,omitempty"`
	// Local lists where the same token is configured on this machine.
	Local     []string   `json:"local,omitempty"`
	Locations []Location `json:"locations"`
	// Occurrences counts objects the token appears in, across all locations.
	Occurrences int `json:"occurrences"`
}

// Active reports whether GitHub confirmed the token as live.
func (f Finding) Active() bool {
	return f.Verification != nil && f.Verification.Status == detect.StatusActive
}

// Revoked reports whether GitHub confirmed the token as dead.
func (f Finding) Revoked() bool {
	return f.Verification != nil && f.Verification.Status == detect.StatusRevoked
}

// Stats summarises one repository scan.
type Stats struct {
	Objects     int           `json:"objects"`
	Scanned     int           `json:"scanned"`
	Skipped     int           `json:"skipped_large"`
	Bytes       int64         `json:"bytes"`
	Refs        int           `json:"refs"`
	Orphaned    int           `json:"orphaned_commits"`
	Rewrites    int           `json:"rewrites_fetched"`
	Unavailable int           `json:"rewrites_unavailable"`
	Disk        int64         `json:"disk_bytes,omitempty"`
	Duration    time.Duration `json:"-"`
}

// Result is the outcome for one target.
type Result struct {
	Target   string    `json:"target"`
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
	Notes    []string  `json:"notes,omitempty"`
	Err      error     `json:"-"`
	Error    string    `json:"error,omitempty"`
	Skipped  bool      `json:"skipped,omitempty"`
}

type hit struct {
	object gitrepo.Object
	line   int
}

// Repo scans every blob, commit and tag object of the repository and
// attributes findings. rewrites annotate commits fetched by SHA.
func Repo(ctx context.Context, name string, repo *gitrepo.Repo, rewrites []Rewrite, opts Options) (Result, error) {
	start := time.Now()
	res := Result{Target: name}

	objs, err := repo.Objects(ctx)
	if err != nil {
		return res, err
	}
	res.Stats.Objects = len(objs)
	var (
		shas    []string
		commits []string
	)
	for _, o := range objs {
		switch o.Type {
		case "commit":
			commits = append(commits, o.SHA)
		case "blob", "tag":
		default:
			continue
		}
		if opts.MaxObject > 0 && o.Size > opts.MaxObject {
			res.Stats.Skipped++
			continue
		}
		shas = append(shas, o.SHA)
	}

	var (
		mu       sync.Mutex
		bytes    int64
		findings = map[string]*Finding{}
		hits     = map[string]map[hit]bool{} // token value -> distinct locations
	)
	err = parallel(ctx, shas, opts.workers(), func(shard []string) error {
		var local int64
		err := repo.ReadObjects(ctx, shard, func(obj gitrepo.Object, content []byte) error {
			local += obj.Size
			for _, tok := range detect.Find(content) {
				if opts.Ignore[tok.Fingerprint()] {
					continue
				}
				mu.Lock()
				f := findings[tok.Value]
				if f == nil {
					f = &Finding{Kind: tok.Kind, Fingerprint: tok.Fingerprint(), Token: tok.Value, Redacted: detect.Redact(tok.Value), ChecksumVerified: tok.ChecksumVerified}
					findings[tok.Value] = f
					hits[tok.Value] = map[hit]bool{}
				}
				f.Occurrences++
				hits[tok.Value][hit{obj, tok.Line}] = true
				mu.Unlock()
			}
			return nil
		})
		mu.Lock()
		bytes += local
		mu.Unlock()
		return err
	})
	if err != nil {
		return res, err
	}
	res.Stats.Scanned = len(shas)
	res.Stats.Bytes = bytes

	if len(findings) > 0 {
		if err := attribute(ctx, name, repo, commits, rewrites, findings, hits, &res.Stats); err != nil {
			return res, err
		}
	}
	for _, f := range findings {
		if opts.Verifier != nil {
			v := opts.Verifier.Verify(ctx, detect.Token{Kind: f.Kind, Value: f.Token})
			f.Verification = &v
		}
		res.Findings = append(res.Findings, *f)
	}
	SortFindings(res.Findings)
	res.Stats.Duration = time.Since(start)
	return res, nil
}

// SortFindings orders active tokens first, then by kind and fingerprint.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if a, b := rank(fs[i]), rank(fs[j]); a != b {
			return a < b
		}
		if fs[i].Kind != fs[j].Kind {
			return fs[i].Kind < fs[j].Kind
		}
		return fs[i].Fingerprint < fs[j].Fingerprint
	})
}

func rank(f Finding) int {
	if f.Verification == nil {
		return 1
	}
	switch f.Verification.Status {
	case detect.StatusActive:
		return 0
	case detect.StatusUnknown, detect.StatusUnverifiable:
		return 1
	default:
		return 2
	}
}

// attribute resolves paths, introducing commits and refs for every hit.
func attribute(ctx context.Context, name string, repo *gitrepo.Repo, commits []string, rewrites []Rewrite, findings map[string]*Finding, hits map[string]map[hit]bool, stats *Stats) error {
	reachable, err := repo.ReachableCommits(ctx)
	if err != nil {
		return err
	}
	var orphanRoots []string
	for _, c := range commits {
		if !reachable[c] {
			orphanRoots = append(orphanRoots, c)
		}
	}
	stats.Orphaned = len(orphanRoots)

	paths, err := repo.ObjectPaths(ctx, nil)
	if err != nil {
		return err
	}
	if len(orphanRoots) > 0 {
		orphanPaths, err := repo.ObjectPaths(ctx, orphanRoots)
		if err != nil {
			return err
		}
		for sha, p := range orphanPaths {
			if _, ok := paths[sha]; !ok {
				paths[sha] = p
			}
		}
	}

	type attribution struct {
		path   string
		commit *gitrepo.Commit
	}
	objects := map[string]attribution{}
	refsOf := map[string][]string{}
	rewriteOf := map[string]string{}
	for value, locs := range hits {
		f := findings[value]
		for h := range locs {
			a, ok := objects[h.object.SHA]
			if !ok {
				a.path = paths[h.object.SHA]
				if h.object.Type == "commit" {
					a.commit, err = repo.Commit(ctx, h.object.SHA)
				} else {
					a.commit, err = repo.IntroducingCommit(ctx, h.object.SHA, nil)
					if err == nil && a.commit == nil && len(orphanRoots) > 0 {
						a.commit, err = repo.IntroducingCommit(ctx, h.object.SHA, orphanRoots)
					}
				}
				if err != nil {
					return err
				}
				objects[h.object.SHA] = a
			}
			loc := Location{Repo: name, Object: h.object.SHA, ObjectType: h.object.Type, Path: a.path, Line: h.line, Commit: a.commit}
			if a.commit != nil {
				refs, ok := refsOf[a.commit.SHA]
				if !ok {
					if refs, err = repo.RefsContaining(ctx, a.commit.SHA); err != nil {
						return err
					}
					refsOf[a.commit.SHA] = refs
					if len(refs) == 0 {
						for _, rw := range rewrites {
							if repo.IsAncestor(ctx, a.commit.SHA, rw.SHA) {
								rewriteOf[a.commit.SHA] = rw.Description
								break
							}
						}
					}
				}
				loc.Refs = refs
				loc.Orphaned = len(refs) == 0
				loc.Rewrite = rewriteOf[a.commit.SHA]
			}
			f.Locations = append(f.Locations, loc)
		}
		sort.Slice(f.Locations, func(i, j int) bool {
			a, b := f.Locations[i], f.Locations[j]
			if a.Commit != nil && b.Commit != nil && a.Commit.Date != b.Commit.Date {
				return a.Commit.Date < b.Commit.Date
			}
			if a.Path != b.Path {
				return a.Path < b.Path
			}
			return a.Line < b.Line
		})
	}
	return nil
}

// parallel splits items into contiguous shards and runs fn on each
// concurrently, returning the first error.
func parallel(ctx context.Context, items []string, workers int, fn func([]string) error) error {
	if len(items) == 0 {
		return nil
	}
	workers = min(workers, len(items))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg    sync.WaitGroup
		once  sync.Once
		first error
	)
	per := (len(items) + workers - 1) / workers
	for start := 0; start < len(items); start += per {
		shard := items[start:min(start+per, len(items))]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(shard); err != nil {
				once.Do(func() {
					first = err
					cancel()
				})
			}
		}()
	}
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}

// Summary aggregates results for the final line of a report.
type Summary struct {
	Repos    int
	Failed   int
	Skipped  int
	Tokens   int
	Active   int
	Bytes    int64
	Objects  int
	Duration time.Duration
}

// Summarize computes totals; tokens seen in several repositories count once.
func Summarize(results []Result) Summary {
	s := Summary{}
	seen := map[string]bool{}
	for _, r := range results {
		s.Repos++
		switch {
		case r.Skipped:
			s.Skipped++
		case r.Err != nil:
			s.Failed++
		}
		s.Bytes += r.Stats.Bytes
		s.Objects += r.Stats.Scanned
		for _, f := range r.Findings {
			if seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true
			s.Tokens++
			if f.Verification != nil && f.Verification.Status == detect.StatusActive {
				s.Active++
			}
		}
	}
	return s
}

// Describe renders the stats of one result as a compact status line.
func Describe(r Result) string {
	if r.Skipped {
		return "skipped: " + r.Error
	}
	if r.Err != nil {
		return "failed: " + r.Err.Error()
	}
	st := r.Stats
	s := fmt.Sprintf("%d objects · %s · %s", st.Scanned, humanBytes(st.Bytes), st.Duration.Round(time.Millisecond))
	if st.Refs > 0 {
		s += fmt.Sprintf(" · %d refs", st.Refs)
	}
	if st.Orphaned > 0 {
		s += fmt.Sprintf(" · %d orphaned commits", st.Orphaned)
	}
	if st.Rewrites > 0 {
		s += fmt.Sprintf(" · %d rewritten commits fetched", st.Rewrites)
	}
	if st.Skipped > 0 {
		s += fmt.Sprintf(" · %d large objects skipped", st.Skipped)
	}
	return s
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
