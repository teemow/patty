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
	"github.com/teemow/patty/internal/detect/providers"
	"github.com/teemow/patty/internal/gitrepo"
)

// Options tune a repository scan.
type Options struct {
	// Workers is the number of parallel `git cat-file` readers.
	Workers int
	// MaxObject skips objects larger than this many bytes.
	MaxObject int64
	// Ignore holds the token fingerprints and credential kinds to leave out
	// of the results.
	Ignore map[string]bool
	// Providers is the set of credential providers to look for; nil means
	// every provider patty ships with.
	Providers *detect.Registry
	// Verify checks each credential found against its provider's API.
	Verify bool
}

func (o Options) providers() *detect.Registry {
	if o.Providers != nil {
		return o.Providers
	}
	return providers.Default()
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

// Finding is one distinct credential and everywhere it appears.
type Finding struct {
	// Provider names the issuer of the credential: GitHub, Slack.
	Provider    string      `json:"provider"`
	Kind        detect.Kind `json:"kind"`
	Fingerprint string      `json:"fingerprint"`
	Token       string      `json:"-"`
	// Secret is the companion material of a credential made of several
	// strings, when it was found next to the token; see detect.Token.Secret.
	Secret           string `json:"-"`
	Redacted         string `json:"token"`
	ChecksumVerified bool   `json:"checksum_verified"`
	// Attribution is what the credential's own shape says about its owner,
	// such as the workspace id in a Slack token; known without --verify.
	Attribution string `json:"attribution,omitempty"`
	// Opaque marks secret material of no recognised shape, a plaintext
	// Kubernetes Secret, which nothing can verify; see detect.KindInfo.
	Opaque       bool                 `json:"opaque,omitempty"`
	Verification *detect.Verification `json:"verification,omitempty"`
	// Revocation records what happened when patty asked the provider to revoke the credential.
	Revocation Revocation `json:"revocation,omitempty"`
	// Local lists where the same token is configured on this machine.
	Local []string `json:"local,omitempty"`
	// Unlocks lists the files in the scanned repositories the credential
	// opens, when its provider correlates findings with the content around
	// them: the sops files encrypted to an age identity.
	Unlocks   []Unlock   `json:"unlocks,omitempty"`
	Locations []Location `json:"locations"`
	// Occurrences counts objects the token appears in, across all locations.
	Occurrences int `json:"occurrences"`
}

// Unlock is one file a credential opens; see Finding.Unlocks.
type Unlock struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
}

// Active reports whether the provider confirmed the credential as live.
func (f Finding) Active() bool {
	return f.Verification != nil && f.Verification.Status == detect.StatusActive
}

// Revoked reports whether the provider confirmed the credential as dead.
func (f Finding) Revoked() bool {
	return f.Verification != nil && f.Verification.Status == detect.StatusRevoked
}

// Unverifiable reports whether the credential cannot be checked against its
// provider, so no verdict about it will ever come.
func (f Finding) Unverifiable() bool {
	return f.Verification != nil && f.Verification.Status == detect.StatusUnverifiable
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
		mu          sync.Mutex
		bytes       int64
		findings    = map[string]*Finding{}
		hits        = map[string]map[hit]bool{} // token value -> distinct locations
		registry    = opts.providers()
		correlators = registry.Correlators()
		sightings   = map[string][]string{} // blob -> identifiers it names, per correlators
	)
	err = parallel(ctx, shas, opts.workers(), func(shard []string) error {
		var local int64
		err := repo.ReadObjects(ctx, shard, func(obj gitrepo.Object, content []byte) error {
			local += obj.Size
			if obj.Type == "blob" {
				for _, c := range correlators {
					if ids := c.Observe(content); len(ids) > 0 {
						mu.Lock()
						sightings[obj.SHA] = append(sightings[obj.SHA], ids...)
						mu.Unlock()
					}
				}
			}
			for _, tok := range registry.Find(content) {
				if opts.Ignore[tok.Fingerprint()] || opts.Ignore[string(tok.Kind)] {
					continue
				}
				mu.Lock()
				f := findings[tok.Value]
				if f == nil {
					f = NewFinding(registry, tok)
					findings[tok.Value] = f
					hits[tok.Value] = map[hit]bool{}
				} else {
					f.complete(tok.Secret, tok.Attribution)
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
		paths, err := attribute(ctx, name, repo, commits, rewrites, findings, hits, &res.Stats)
		if err != nil {
			return res, err
		}
		correlate(name, registry, findings, sightings, paths)
	}
	for _, f := range findings {
		if opts.Verify {
			v := registry.Verify(ctx, f.Detected())
			f.Verification = &v
		}
		res.Findings = append(res.Findings, *f)
	}
	SortFindings(res.Findings)
	res.Stats.Duration = time.Since(start)
	return res, nil
}

// NewFinding starts the finding for a credential: provider, kind,
// fingerprint and redacted value, with no locations yet.
func NewFinding(registry *detect.Registry, tok detect.Token) *Finding {
	redacted := detect.Redact(tok.Value)
	if registry.Info(tok.Kind).PublicValue {
		redacted = tok.Value
	}
	return &Finding{
		Provider:         registry.ProviderName(tok.Kind),
		Kind:             tok.Kind,
		Fingerprint:      tok.Fingerprint(),
		Token:            tok.Value,
		Redacted:         redacted,
		ChecksumVerified: tok.ChecksumVerified,
		Attribution:      tok.Attribution,
		Opaque:           registry.Info(tok.Kind).Opaque,
		Secret:           tok.Secret,
	}
}

// Detected rebuilds the detect.Token a finding stands for.
func (f Finding) Detected() detect.Token {
	return detect.Token{Kind: f.Kind, Value: f.Token, Secret: f.Secret}
}

// complete takes over the companion secret and attribution of another
// occurrence of the same credential when that occurrence carries more of it:
// a key id that appears once with its secret and once without is one key
// pair.
func (f *Finding) complete(secret, attribution string) {
	if len(secret) > len(f.Secret) {
		f.Secret, f.Attribution = secret, attribution
	}
}

// SortFindings orders active credentials first, then the ones nothing has
// rejected, then opaque material nothing can verify, then the rejected
// ones; within a group by kind and fingerprint.
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
	if f.Verification != nil {
		switch f.Verification.Status {
		case detect.StatusActive:
			return 0
		case detect.StatusRevoked:
			return 3
		}
	}
	if f.Opaque {
		return 2
	}
	return 1
}

// correlate lists on every finding of a correlating provider the files of
// this repository that name the credential: the sops files encrypted to an
// identity's recipient. Every version of a file counts once; a blob no
// commit reaches has no path and is left out.
func correlate(repo string, registry *detect.Registry, findings map[string]*Finding, sightings map[string][]string, paths map[string]string) {
	if len(sightings) == 0 {
		return
	}
	pathsOf := map[string]map[string]bool{} // identifier -> paths naming it
	for sha, ids := range sightings {
		path := paths[sha]
		if path == "" {
			continue
		}
		for _, id := range ids {
			if pathsOf[id] == nil {
				pathsOf[id] = map[string]bool{}
			}
			pathsOf[id][path] = true
		}
	}
	for _, f := range findings {
		c, ok := registry.Provider(f.Kind).(detect.Correlator)
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, id := range c.Identifiers(f.Detected()) {
			for path := range pathsOf[id] {
				if !seen[path] {
					seen[path] = true
					f.Unlocks = append(f.Unlocks, Unlock{Repo: repo, Path: path})
				}
			}
		}
		sort.Slice(f.Unlocks, func(i, j int) bool { return f.Unlocks[i].Path < f.Unlocks[j].Path })
	}
}

// attribute resolves paths, introducing commits and refs for every hit. It
// returns the path of every object it could map, for correlate.
func attribute(ctx context.Context, name string, repo *gitrepo.Repo, commits []string, rewrites []Rewrite, findings map[string]*Finding, hits map[string]map[hit]bool, stats *Stats) (map[string]string, error) {
	reachable, err := repo.ReachableCommits(ctx)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	if len(orphanRoots) > 0 {
		orphanPaths, err := repo.ObjectPaths(ctx, orphanRoots)
		if err != nil {
			return nil, err
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
					return nil, err
				}
				objects[h.object.SHA] = a
			}
			loc := Location{Repo: name, Object: h.object.SHA, ObjectType: h.object.Type, Path: a.path, Line: h.line, Commit: a.commit}
			if a.commit != nil {
				refs, ok := refsOf[a.commit.SHA]
				if !ok {
					if refs, err = repo.RefsContaining(ctx, a.commit.SHA); err != nil {
						return nil, err
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
	return paths, nil
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
