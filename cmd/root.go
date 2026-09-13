// Package cmd wires the patty command line.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/gitlab"
	"github.com/teemow/patty/internal/detect/grafana"
	"github.com/teemow/patty/internal/detect/providers"
	"github.com/teemow/patty/internal/disk"
	"github.com/teemow/patty/internal/github"
	"github.com/teemow/patty/internal/gitrepo"
	"github.com/teemow/patty/internal/localcreds"
	"github.com/teemow/patty/internal/report"
	"github.com/teemow/patty/internal/scan"
	"github.com/teemow/patty/internal/source"
)

// Exit codes.
const (
	ExitClean    = 0
	ExitFindings = 1
	ExitError    = 2
)

var version = "dev"

// SetVersion records the build version for `patty version`.
func SetVersion(v string) {
	version = v
	rootCmd.Version = v
}

type flags struct {
	verify          bool
	verifyPrivate   bool
	revoke          bool
	yes             bool
	jsonOut         bool
	showSecrets     bool
	allRefs         bool
	keep            bool
	cacheDir        string
	maxDisk         string
	minFree         string
	maxObject       string
	workers         int
	parallel        int
	noRewrites      bool
	activityPages   int
	includeForks    bool
	includeArchived bool
	files           bool
	ignore          []string
	grafanaURLs     []string
	gitlabURLs      []string
	verbose         bool
}

// env is the process environment as the providers see it: the operator's
// --grafana-url and --gitlab-url are added to GRAFANA_URL and GITLAB_URL,
// which is how those providers take their instances.
func (f flags) env(name string) string {
	var extra []string
	switch name {
	case grafana.URLEnv:
		extra = f.grafanaURLs
	case gitlab.URLEnv:
		extra = f.gitlabURLs
	}
	if len(extra) == 0 {
		return os.Getenv(name)
	}
	return strings.Join(append(extra, os.Getenv(name)), ",")
}

// defaults are the flag values patty starts from. The cache subcommand,
// which has no flags of its own, uses them as they are.
func defaults() flags {
	return flags{cacheDir: defaultCacheDir(), maxDisk: "20G", minFree: "2G", maxObject: "10M", workers: runtime.NumCPU(), parallel: 2, activityPages: 10, includeArchived: true}
}

var rootCmd = newRootCmd()

// newRootCmd builds the root command with flags of its own, so tests run it
// fresh. The provider registry is built when the command runs, not when the
// package loads: Configure reads the environment.
func newRootCmd() *cobra.Command {
	opts := defaults()
	cmd := &cobra.Command{
		Use:   "patty [target...]",
		Short: "Finds leaked credentials in every corner of a repository's history, including the commits a clone never shows",
		Long: `Patty checks the credentials in your git history -- all of it.

A target is a local path, an owner/repo, a github.com URL, or a bare owner
(user or organization) to scan every repository of. A local repository is
scanned through its object database, reflog and stashes included; a
directory that is not a repository, or a single file, is scanned file by
file as it is on disk, and --files does that for the working tree of a
repository too, so untracked and ignored files are covered.

GitHub repositories are mirrored into a size-capped cache (all branches,
tags and pull request refs), extended with commits the repository activity
feed reports as force-pushed away or deleted, and every object in the
database is scanned -- reachable or not. Every credential kind patty knows
belongs to a provider that finds it offline, verifying a built-in checksum
where the format has one, and says what the shape alone reveals: the
account an AWS key belongs to, the sops files an age identity decrypts, the
certificates, authorized_keys files, image policies and GitHub accounts
that trust a private key. The values of every Kubernetes Secret manifest
are decoded and searched for all of them, and a Secret committed with
plaintext values is reported on its own (kind kubernetes-secret-manifest;
--ignore takes kinds as well as fingerprints).

--verify asks each provider whether a credential is still live, and
--revoke asks it to revoke the live ones. A provider whose API cannot
revoke a key by itself takes the organization's admin key from the
environment (ANTHROPIC_ADMIN_KEY, OPENAI_ADMIN_KEY). Kubernetes
credentials are checked against the API server their kubeconfig names,
over https only and never on a private network unless
--verify-private-servers is given. A Grafana or GitLab token does not
name the instance that issued it: it is checked against the instances
named with --grafana-url or --gitlab-url (or GRAFANA_URL, GITLAB_URL),
and against the Grafana and GitLab hosts the scanned content itself
names, under the same restrictions. An unencrypted SSH key is offered
to github.com once, with no command, after GitHub's published host key
fingerprints were checked. A PagerDuty routing key is never verified:
the only test would page the on-call.

Every credential comes with advice: where its owner revokes it, whether it
is still configured on this machine, and what its history needs.

Exit code 0 means nothing was found, 1 that credentials were found, 2 that
a target failed or was skipped and nothing was found.`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, opts, providers.New(opts.env))
		},
	}
	f := cmd.Flags()
	f.BoolVar(&opts.verify, "verify", false, "Check each credential against its provider's API to tell active ones from revoked ones")
	f.BoolVar(&opts.verifyPrivate, "verify-private-servers", false, "With --verify, also contact API servers, Grafana and GitLab instances and npm registries on private, loopback or link-local addresses named in the scanned content")
	f.StringArrayVar(&opts.grafanaURLs, "grafana-url", nil, "Grafana instance to check service account tokens and API keys against with --verify (repeatable; also GRAFANA_URL)")
	f.StringArrayVar(&opts.gitlabURLs, "gitlab-url", nil, "Self-managed GitLab instance to check tokens against with --verify, besides gitlab.com (repeatable; also GITLAB_URL)")
	f.BoolVar(&opts.revoke, "revoke", false, "Ask the provider to revoke every active credential found (implies --verify; asks for confirmation)")
	f.BoolVarP(&opts.yes, "yes", "y", false, "Revoke without asking for confirmation")
	f.BoolVar(&opts.jsonOut, "json", false, "Print results as JSON")
	f.BoolVar(&opts.showSecrets, "show-secrets", false, "Print full token values instead of redacted ones")
	f.BoolVar(&opts.allRefs, "all-refs", false, "List every branch, tag and pull request a commit is on instead of the first five")
	f.BoolVar(&opts.keep, "keep", false, "Keep mirrors in the cache after scanning (faster re-runs, bounded by --max-disk)")
	f.StringVar(&opts.cacheDir, "cache-dir", opts.cacheDir, "Directory for repository mirrors")
	f.StringVar(&opts.maxDisk, "max-disk", opts.maxDisk, "Total size the mirror cache may occupy")
	f.StringVar(&opts.minFree, "min-free", opts.minFree, "Free space that must remain on the cache drive")
	f.StringVar(&opts.maxObject, "max-object", opts.maxObject, "Skip objects larger than this")
	f.IntVar(&opts.workers, "workers", opts.workers, "Parallel object readers per repository")
	f.IntVar(&opts.parallel, "parallel", opts.parallel, "Repositories processed at once")
	f.BoolVar(&opts.noRewrites, "no-rewrites", false, "Do not fetch force-pushed or deleted commits reported by the activity feed")
	f.IntVar(&opts.activityPages, "activity-pages", opts.activityPages, "Activity feed pages (100 events each) to read per repository and event type")
	f.BoolVar(&opts.includeForks, "include-forks", false, "Include forks when expanding an owner")
	f.BoolVar(&opts.includeArchived, "include-archived", opts.includeArchived, "Include archived repositories when expanding an owner")
	f.BoolVar(&opts.files, "files", false, "Also scan the files of a local repository as they are on disk, untracked and ignored ones included (implied for a directory that is not a repository)")
	f.StringSliceVar(&opts.ignore, "ignore", nil, "Credential fingerprints or kinds to leave out of the report (comma-separated)")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "Print progress for each phase")
	return cmd
}

// Execute runs the command and returns the process exit code.
func Execute() (int, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return exit(rootCmd.ExecuteContext(ctx))
}

// exit maps what a command returned to the process exit code: a clean run
// is 0, a run that chose its own code (findings, failures) keeps it, and
// any other error is reported by the caller with code 2.
func exit(err error) (int, error) {
	var ec exitCode
	switch {
	case err == nil:
		return ExitClean, nil
	case errors.As(err, &ec):
		return int(ec), nil
	}
	return ExitError, err
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func defaultCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "patty")
	}
	return filepath.Join(os.TempDir(), "patty")
}

func run(cmd *cobra.Command, args []string, opts flags, registry *detect.Registry) error {
	if len(args) == 0 {
		return cmd.Help()
	}
	ctx := cmd.Context()
	stderr := cmd.ErrOrStderr()
	colors := isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == ""
	ropts := report.Options{Color: colors, ShowSecrets: opts.showSecrets, AllRefs: opts.allRefs, Providers: registry}
	if opts.revoke {
		opts.verify = true
	}
	registry.AllowPrivateServers(opts.verifyPrivate)

	cache, err := newCache(opts)
	if err != nil {
		return err
	}
	maxObject, err := disk.ParseSize(opts.maxObject)
	if err != nil {
		return fmt.Errorf("--max-object: %w", err)
	}

	client, auth, err := githubAccess(args, stderr)
	if err != nil {
		return err
	}

	targets, err := source.Resolve(ctx, client, args, source.Options{ListOptions: github.ListOptions{IncludeForks: opts.includeForks, IncludeArchived: opts.includeArchived}, Files: opts.files})
	if err != nil {
		return err
	}
	if len(targets) > 1 {
		_, _ = fmt.Fprintf(stderr, "Scanning %d %s (cache %s, budget %s)\n", len(targets), targetsWord(targets), cache.Dir, disk.FormatSize(cache.MaxBytes))
	}

	ignore := map[string]bool{}
	for _, fp := range opts.ignore {
		ignore[strings.TrimSpace(fp)] = true
	}
	runOpts := scan.RunOptions{
		Options:       scan.Options{Workers: opts.workers, MaxObject: maxObject, Ignore: ignore, Providers: registry, Verify: opts.verify},
		Cache:         cache,
		Keep:          opts.keep,
		Auth:          auth,
		GitHub:        client,
		Rewrites:      !opts.noRewrites,
		ActivityPages: opts.activityPages,
		Parallel:      opts.parallel,
	}
	if opts.verbose {
		runOpts.Progress = func(target, msg string) { _, _ = fmt.Fprintf(stderr, "  %s: %s\n", target, msg) }
	}

	results := scan.Run(ctx, targets, runOpts, func(r scan.Result) {
		_, _ = fmt.Fprintln(stderr, report.StatusLine(r, ropts))
	})
	if scan.Summarize(results).Tokens > 0 {
		scan.AnnotateLocal(results, localcreds.Match(localcreds.Find(ctx, registry)))
	}
	if opts.revoke && ctx.Err() == nil {
		r := revocation{registry: registry, yes: opts.yes}
		if err := r.active(cmd, results); err != nil {
			return err
		}
	}

	if opts.jsonOut {
		if err := report.JSON(cmd.OutOrStdout(), results, ropts); err != nil {
			return err
		}
	} else {
		report.Text(cmd.OutOrStdout(), results, ropts)
	}
	if err := ctx.Err(); err != nil {
		return errors.New("interrupted")
	}

	s := scan.Summarize(results)
	switch {
	case s.Tokens > 0:
		return exitCode(ExitFindings)
	case s.Failed > 0 || s.Skipped > 0:
		return exitCode(ExitError)
	}
	return nil
}

// targetsWord says what a batch of targets is made of: repositories, or
// targets when a plain directory or file is among them.
func targetsWord(targets []source.Target) string {
	for _, t := range targets {
		if t.Files() {
			return "targets"
		}
	}
	return "repositories"
}

// githubAccess returns the API client and git credentials for the targets
// that are not local paths, or nil when every target is one.
func githubAccess(args []string, stderr io.Writer) (*github.Client, *gitrepo.Auth, error) {
	if !needsGitHub(args) {
		return nil, nil, nil
	}
	token := github.Token()
	var auth *gitrepo.Auth
	if token == "" {
		_, _ = fmt.Fprintln(stderr, "warning: no GitHub token (GITHUB_TOKEN, GH_TOKEN or gh auth); using anonymous access: public repositories only, 60 API requests per hour")
	} else {
		auth = &gitrepo.Auth{Token: token}
	}
	client, err := github.NewClient(token)
	if err != nil {
		return nil, nil, err
	}
	return client, auth, nil
}

// needsGitHub reports whether any target is something other than a path
// that exists on this machine.
func needsGitHub(args []string) bool {
	for _, a := range args {
		if _, err := os.Stat(a); err != nil {
			return true
		}
	}
	return false
}

func newCache(opts flags) (*disk.Cache, error) {
	maxDisk, err := disk.ParseSize(opts.maxDisk)
	if err != nil {
		return nil, fmt.Errorf("--max-disk: %w", err)
	}
	minFree, err := disk.ParseSize(opts.minFree)
	if err != nil {
		return nil, fmt.Errorf("--min-free: %w", err)
	}
	return &disk.Cache{Dir: opts.cacheDir, MaxBytes: maxDisk, MinFree: minFree}, nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
