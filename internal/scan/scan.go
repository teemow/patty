// Package scan runs the detector over every object of a repository and
// attributes what it finds to commits, paths and refs.
package scan

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/disk"
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
	// Providers is the set of credential providers to look for. It is
	// required: the caller assembles it, so this package need not know any
	// provider. A nil registry is a programming error and panics.
	Providers *detect.Registry
	// Verify checks each credential found against its provider's API.
	Verify bool
}

func (o Options) providers() *detect.Registry {
	if o.Providers == nil {
		panic("scan: Options.Providers is nil")
	}
	return o.Providers
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

// Remote is what the hosting service knows about a repository beyond its
// objects: the commits its activity feed reports as rewritten, and the
// logins of its contributors. A local repository has neither.
type Remote struct {
	Rewrites []Rewrite
	// Contributors are GitHub logins, as the repository's contributors
	// endpoint lists them; the scan adds the logins it reads from noreply
	// author addresses itself.
	Contributors []string
}

// maxLogins caps the logins looked up per repository, so a repository with
// thousands of contributors costs at most that many public requests.
const maxLogins = 50

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
	// Encrypted marks passphrase-protected material, useless without a
	// passphrase that may or may not have leaked with it; see detect.Token.
	Encrypted bool `json:"encrypted,omitempty"`
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

// Unlock is one file a credential opens or that names it; see
// Finding.Unlocks.
type Unlock struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
	// Detail is what the file says about the credential when the path
	// alone does not: the names and expiry of the certificate a private
	// key belongs to.
	Detail string `json:"detail,omitempty"`
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
// attributes findings. remote annotates commits fetched by SHA and names
// the repository's contributors.
func Repo(ctx context.Context, name string, repo *gitrepo.Repo, remote Remote, opts Options) (Result, error) {
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
		mu        sync.Mutex
		bytes     int64
		findings  = map[string]*Finding{}
		hits      = map[string]map[hit]bool{} // token value -> distinct locations
		registry  = opts.providers()
		sightings = map[string][]detect.Sighting{} // blob -> identifiers it names, per correlators
		logins    = map[string]bool{}              // GitHub logins read from noreply author addresses
	)
	err = parallel(ctx, shas, opts.workers(), func(shard []string) error {
		var local int64
		err := repo.ReadObjects(ctx, shard, func(obj gitrepo.Object, content []byte) error {
			local += obj.Size
			switch obj.Type {
			case "blob":
				if seen := registry.Observe(content); len(seen) > 0 {
					mu.Lock()
					sightings[obj.SHA] = append(sightings[obj.SHA], seen...)
					mu.Unlock()
				}
			case "commit":
				if found := noreplyLogins(content); len(found) > 0 {
					mu.Lock()
					for _, l := range found {
						logins[l] = true
					}
					mu.Unlock()
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
		paths, err := attribute(ctx, name, repo, commits, remote.Rewrites, findings, hits, &res.Stats)
		if err != nil {
			return res, err
		}
		correlate(ctx, name, registry, findings, sightings, paths, committers(logins, remote.Contributors))
		for value, f := range findings {
			if opts.Ignore[string(f.Kind)] {
				delete(findings, value)
			}
		}
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
		Encrypted:        tok.Encrypted,
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
// ones; within a group material that is usable as it is before
// passphrase-protected material, then by kind and fingerprint.
func SortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if a, b := rank(fs[i]), rank(fs[j]); a != b {
			return a < b
		}
		if fs[i].Encrypted != fs[j].Encrypted {
			return !fs[i].Encrypted
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
// identity's recipient, the authorized_keys that lists a key's public half,
// the certificate a TLS key belongs to. Every version of a file counts
// once; a blob no commit reaches has no path and is left out. A credential
// that says nothing about its public half adopts what the files next to it
// say; one whose public half a committer publishes on GitHub is attributed
// to that login; and a provider that tells its kinds apart by such context
// gets to reclassify the finding.
func correlate(ctx context.Context, repo string, registry *detect.Registry, findings map[string]*Finding, sightings map[string][]detect.Sighting, paths map[string]string, logins []string) {
	if len(sightings) == 0 && len(logins) == 0 {
		return
	}
	type sightingAt struct {
		path string
		detect.Sighting
	}
	var (
		pathsOf = map[string]map[string]string{} // identifier -> path -> detail
		byDir   = map[string][]sightingAt{}      // directory -> sightings in it
		matches = map[detect.CommitterCorrelator]map[string]string{}
	)
	for sha, seen := range sightings {
		p := paths[sha]
		if p == "" {
			continue
		}
		for _, s := range seen {
			if pathsOf[s.ID] == nil {
				pathsOf[s.ID] = map[string]string{}
			}
			if pathsOf[s.ID][p] == "" {
				pathsOf[s.ID][p] = s.Detail
			}
			byDir[path.Dir(p)] = append(byDir[path.Dir(p)], sightingAt{p, s})
		}
	}
	for _, f := range findings {
		provider := registry.Provider(f.Kind)
		c, ok := provider.(detect.Correlator)
		if !ok {
			continue
		}
		tok := f.Detected()
		ids := c.Identifiers(tok)
		if near, ok := provider.(detect.ProximityCorrelator); ok {
			for _, dir := range f.dirs() {
				for _, s := range byDir[dir] {
					ids = appendUnique(ids, near.Adjacent(f.Kind, s.Sighting)...)
				}
			}
		}
		var matched []string
		if cc, ok := provider.(detect.CommitterCorrelator); ok && len(logins) > 0 {
			if matches[cc] == nil {
				matches[cc] = cc.Committers(ctx, logins)
			}
			for _, id := range ids {
				if m := matches[cc][id]; m != "" {
					matched = appendUnique(matched, id)
					f.Attribution = joinAttribution(f.Attribution, m)
				}
			}
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if len(pathsOf[id]) > 0 {
				matched = appendUnique(matched, id)
			}
			for p, detail := range pathsOf[id] {
				if !seen[p] {
					seen[p] = true
					f.Unlocks = append(f.Unlocks, Unlock{Repo: repo, Path: p, Detail: detail})
				}
			}
		}
		sort.Slice(f.Unlocks, func(i, j int) bool { return f.Unlocks[i].Path < f.Unlocks[j].Path })
		if pc, ok := provider.(detect.PathClassifier); ok {
			if kind := pc.Classify(tok, f.paths(), matched); kind != "" && kind != f.Kind && registry.Provider(kind) == provider {
				f.Kind = kind
			}
		}
	}
}

// paths lists the distinct paths a finding was found under, sorted.
func (f Finding) paths() []string {
	var out []string
	for _, l := range f.Locations {
		if l.Path != "" {
			out = appendUnique(out, l.Path)
		}
	}
	sort.Strings(out)
	return out
}

// dirs lists the distinct directories a finding was found in.
func (f Finding) dirs() []string {
	var out []string
	for _, p := range f.paths() {
		out = appendUnique(out, path.Dir(p))
	}
	return out
}

func appendUnique(list []string, items ...string) []string {
	for _, item := range items {
		found := false
		for _, have := range list {
			if have == item {
				found = true
				break
			}
		}
		if !found {
			list = append(list, item)
		}
	}
	return list
}

func joinAttribution(attribution, more string) string {
	if attribution == "" {
		return more
	}
	if strings.Contains(attribution, more) {
		return attribution
	}
	return attribution + "; " + more
}

// committers merges the logins read from commits with the contributors
// the hosting service lists, the former first, each once, at most
// maxLogins of them, in a stable order.
func committers(fromCommits map[string]bool, contributors []string) []string {
	var out []string
	for l := range fromCommits {
		out = append(out, l)
	}
	sort.Strings(out)
	for _, l := range contributors {
		if l != "" && !fromCommits[l] {
			out = appendUnique(out, l)
		}
	}
	if len(out) > maxLogins {
		out = out[:maxLogins]
	}
	return out
}

// noreplyHost is the domain of the addresses GitHub gives users who keep
// their email private; the local part is `id+login` or, for accounts
// older than 2017, the bare login.
const noreplyHost = "@users.noreply.github.com"

// noreplyLogins reads the GitHub logins out of a commit object's author
// and committer lines, which is the one place a repository names them
// without asking GitHub.
func noreplyLogins(commit []byte) []string {
	var out []string
	for line := range bytes.Lines(commit) {
		if len(line) == 0 || line[0] == '\n' {
			break // end of the header
		}
		if !bytes.HasPrefix(line, []byte("author ")) && !bytes.HasPrefix(line, []byte("committer ")) {
			continue
		}
		open, closing := bytes.IndexByte(line, '<'), bytes.IndexByte(line, '>')
		if open < 0 || closing < open {
			continue
		}
		email := string(line[open+1 : closing])
		local, ok := strings.CutSuffix(email, noreplyHost)
		if !ok {
			continue
		}
		if _, login, found := strings.Cut(local, "+"); found {
			local = login
		}
		if local != "" {
			out = appendUnique(out, local)
		}
	}
	return out
}

// attribute resolves paths, introducing commits and refs for every hit. It
// returns the path of every object it could map, for correlate.
func attribute(ctx context.Context, name string, repo *gitrepo.Repo, commits []string, rewrites []Rewrite, findings map[string]*Finding, hits map[string]map[hit]bool, stats *Stats) (map[string]string, error) {
	a, err := newAttributor(ctx, name, repo, commits, rewrites)
	if err != nil {
		return nil, err
	}
	stats.Orphaned = len(a.orphanRoots)
	for value, locs := range hits {
		f := findings[value]
		for h := range locs {
			loc, err := a.locate(ctx, h)
			if err != nil {
				return nil, err
			}
			f.Locations = append(f.Locations, loc)
		}
		sortLocations(f.Locations)
	}
	return a.paths, nil
}

// attributor says where a hit sits in a repository: the path of its object,
// the commit that introduced it, and the refs that still reach that commit.
// It remembers each answer, since a credential is usually hit many times in
// the same few objects and commits.
type attributor struct {
	name        string
	repo        *gitrepo.Repo
	orphanRoots []string // commits no ref reaches
	rewrites    []Rewrite
	paths       map[string]string      // object -> path, reachable or orphaned
	objects     map[string]attribution // object -> its path and commit
	refsOf      map[string][]string    // commit -> refs whose history includes it
	rewriteOf   map[string]string      // commit -> how it went unreachable, when known
}

// attribution is what an object is attributed to: its path and the commit
// that introduced it, the commit itself for a commit object.
type attribution struct {
	path   string
	commit *gitrepo.Commit
}

// newAttributor finds the orphaned commits among commits and maps every
// object to a path, through the refs first and the orphaned commits after.
func newAttributor(ctx context.Context, name string, repo *gitrepo.Repo, commits []string, rewrites []Rewrite) (*attributor, error) {
	roots, err := orphanRoots(ctx, repo, commits)
	if err != nil {
		return nil, err
	}
	paths, err := objectPaths(ctx, repo, roots)
	if err != nil {
		return nil, err
	}
	return &attributor{
		name: name, repo: repo, orphanRoots: roots, rewrites: rewrites, paths: paths,
		objects: map[string]attribution{}, refsOf: map[string][]string{}, rewriteOf: map[string]string{},
	}, nil
}

// orphanRoots returns the commits among commits that no ref reaches.
func orphanRoots(ctx context.Context, repo *gitrepo.Repo, commits []string) ([]string, error) {
	reachable, err := repo.ReachableCommits(ctx)
	if err != nil {
		return nil, err
	}
	var roots []string
	for _, c := range commits {
		if !reachable[c] {
			roots = append(roots, c)
		}
	}
	return roots, nil
}

// objectPaths maps every object to a path: the one it has in the reachable
// history, or else the one an orphaned commit gives it.
func objectPaths(ctx context.Context, repo *gitrepo.Repo, orphanRoots []string) (map[string]string, error) {
	paths, err := repo.ObjectPaths(ctx, nil)
	if err != nil || len(orphanRoots) == 0 {
		return paths, err
	}
	orphanPaths, err := repo.ObjectPaths(ctx, orphanRoots)
	if err != nil {
		return nil, err
	}
	for sha, p := range orphanPaths {
		if _, ok := paths[sha]; !ok {
			paths[sha] = p
		}
	}
	return paths, nil
}

// locate builds the Location of one hit.
func (a *attributor) locate(ctx context.Context, h hit) (Location, error) {
	at, err := a.object(ctx, h.object)
	if err != nil {
		return Location{}, err
	}
	loc := Location{Repo: a.name, Object: h.object.SHA, ObjectType: h.object.Type, Path: at.path, Line: h.line, Commit: at.commit}
	if at.commit == nil {
		return loc, nil
	}
	refs, err := a.refs(ctx, at.commit.SHA)
	if err != nil {
		return Location{}, err
	}
	loc.Refs = refs
	loc.Orphaned = len(refs) == 0
	loc.Rewrite = a.rewriteOf[at.commit.SHA]
	return loc, nil
}

// object returns the path and introducing commit of obj, looked up once. A
// blob or tag no reachable commit introduces is tried against the orphaned
// commits.
func (a *attributor) object(ctx context.Context, obj gitrepo.Object) (attribution, error) {
	if at, ok := a.objects[obj.SHA]; ok {
		return at, nil
	}
	at := attribution{path: a.paths[obj.SHA]}
	var err error
	if obj.Type == "commit" {
		at.commit, err = a.repo.Commit(ctx, obj.SHA)
	} else {
		at.commit, err = a.introducingCommit(ctx, obj.SHA)
	}
	if err != nil {
		return attribution{}, err
	}
	a.objects[obj.SHA] = at
	return at, nil
}

func (a *attributor) introducingCommit(ctx context.Context, sha string) (*gitrepo.Commit, error) {
	c, err := a.repo.IntroducingCommit(ctx, sha, nil)
	if err != nil || c != nil || len(a.orphanRoots) == 0 {
		return c, err
	}
	return a.repo.IntroducingCommit(ctx, sha, a.orphanRoots)
}

// refs returns the refs whose history includes the commit, looked up once.
// A commit no ref reaches is matched against the rewrites the hosting
// service reported, so the report can say how it went unreachable.
func (a *attributor) refs(ctx context.Context, commit string) ([]string, error) {
	if refs, ok := a.refsOf[commit]; ok {
		return refs, nil
	}
	refs, err := a.repo.RefsContaining(ctx, commit)
	if err != nil {
		return nil, err
	}
	a.refsOf[commit] = refs
	if len(refs) == 0 {
		a.rewriteOf[commit] = a.rewrite(ctx, commit)
	}
	return refs, nil
}

// rewrite describes the reported rewrite that took the commit with it, or
// "" when none did.
func (a *attributor) rewrite(ctx context.Context, commit string) string {
	for _, rw := range a.rewrites {
		if a.repo.IsAncestor(ctx, commit, rw.SHA) {
			return rw.Description
		}
	}
	return ""
}

// sortLocations orders locations by commit date, then path, then line.
func sortLocations(locs []Location) {
	sort.Slice(locs, func(i, j int) bool {
		a, b := locs[i], locs[j]
		if a.Commit != nil && b.Commit != nil && a.Commit.Date != b.Commit.Date {
			return a.Commit.Date < b.Commit.Date
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
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
	s := fmt.Sprintf("%d objects · %s · %s", st.Scanned, disk.FormatSize(st.Bytes), st.Duration.Round(time.Millisecond))
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
