// Package cmd wires the patty command line.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

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

// registry holds every credential provider patty knows.
var registry = providers.Default()

// SetVersion records the build version for `patty version`.
func SetVersion(v string) {
	version = v
	rootCmd.Version = v
}

type flags struct {
	verify          bool
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
	ignore          []string
	verbose         bool
}

var opts flags

var rootCmd = &cobra.Command{
	Use:   "patty [target...]",
	Short: "Finds leaked GitHub, Slack, AWS and sops credentials in every corner of a repository's history",
	Long: `Patty checks the credentials in your git history -- all of it.

A target is a local repository path, an owner/repo, a github.com URL, or a
bare owner (user or organization) to scan every repository of.

GitHub repositories are mirrored into a size-capped cache (all branches,
tags and pull request refs), extended with commits the repository activity
feed reports as force-pushed away or deleted, and every object in the
database is scanned -- reachable or not. patty looks for GitHub tokens,
Slack tokens and webhooks, AWS access keys, and the age identities and PGP
keys that decrypt sops secrets; for those it also lists the sops files in
the scanned repositories that are encrypted to them. Classic GitHub tokens
and age identities are verified offline against their built-in checksum;
--verify asks each provider whether a credential is still live, and
--revoke asks it to revoke the live ones.

Every credential comes with advice: where its owner revokes it, whether it
is still configured on this machine, and what its history needs.

Exit code 0 means nothing was found, 1 that credentials were found, 2 that
a target failed or was skipped and nothing was found.`,
	Args:          cobra.ArbitraryArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          run,
}

func init() {
	f := rootCmd.Flags()
	f.BoolVar(&opts.verify, "verify", false, "Check each credential against its provider's API to tell active ones from revoked ones")
	f.BoolVar(&opts.revoke, "revoke", false, "Ask the provider to revoke every active credential found (implies --verify; asks for confirmation)")
	f.BoolVarP(&opts.yes, "yes", "y", false, "Revoke without asking for confirmation")
	f.BoolVar(&opts.jsonOut, "json", false, "Print results as JSON")
	f.BoolVar(&opts.showSecrets, "show-secrets", false, "Print full token values instead of redacted ones")
	f.BoolVar(&opts.allRefs, "all-refs", false, "List every branch, tag and pull request a commit is on instead of the first five")
	f.BoolVar(&opts.keep, "keep", false, "Keep mirrors in the cache after scanning (faster re-runs, bounded by --max-disk)")
	f.StringVar(&opts.cacheDir, "cache-dir", defaultCacheDir(), "Directory for repository mirrors")
	f.StringVar(&opts.maxDisk, "max-disk", "20G", "Total size the mirror cache may occupy")
	f.StringVar(&opts.minFree, "min-free", "2G", "Free space that must remain on the cache drive")
	f.StringVar(&opts.maxObject, "max-object", "10M", "Skip objects larger than this")
	f.IntVar(&opts.workers, "workers", runtime.NumCPU(), "Parallel object readers per repository")
	f.IntVar(&opts.parallel, "parallel", 2, "Repositories processed at once")
	f.BoolVar(&opts.noRewrites, "no-rewrites", false, "Do not fetch force-pushed or deleted commits reported by the activity feed")
	f.IntVar(&opts.activityPages, "activity-pages", 10, "Activity feed pages (100 events each) to read per repository and event type")
	f.BoolVar(&opts.includeForks, "include-forks", false, "Include forks when expanding an owner")
	f.BoolVar(&opts.includeArchived, "include-archived", true, "Include archived repositories when expanding an owner")
	f.StringSliceVar(&opts.ignore, "ignore", nil, "Credential fingerprints to leave out of the report (comma-separated)")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "Print progress for each phase")
}

// Execute runs the command and returns the process exit code.
func Execute() (int, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		var ec exitCode
		if errors.As(err, &ec) {
			return int(ec), nil
		}
		return ExitError, err
	}
	return ExitClean, nil
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func defaultCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "patty")
	}
	return filepath.Join(os.TempDir(), "patty")
}

func run(cmd *cobra.Command, args []string) error {
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

	cache, err := newCache()
	if err != nil {
		return err
	}
	maxObject, err := disk.ParseSize(opts.maxObject)
	if err != nil {
		return fmt.Errorf("--max-object: %w", err)
	}

	needGitHub := false
	for _, a := range args {
		if info, err := os.Stat(a); err != nil || !info.IsDir() {
			needGitHub = true
		}
	}
	var (
		client *github.Client
		auth   *gitrepo.Auth
	)
	if needGitHub {
		token := github.Token()
		if token == "" {
			_, _ = fmt.Fprintln(stderr, "warning: no GitHub token (GITHUB_TOKEN, GH_TOKEN or gh auth); using anonymous access: public repositories only, 60 API requests per hour")
		} else {
			auth = &gitrepo.Auth{Token: token}
		}
		if client, err = github.NewClient(token); err != nil {
			return err
		}
	}

	targets, err := source.Resolve(ctx, client, args, github.ListOptions{IncludeForks: opts.includeForks, IncludeArchived: opts.includeArchived})
	if err != nil {
		return err
	}
	if len(targets) > 1 {
		_, _ = fmt.Fprintf(stderr, "Scanning %d repositories (cache %s, budget %s)\n", len(targets), cache.Dir, disk.FormatSize(cache.MaxBytes))
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
		if err := revokeActive(cmd, results); err != nil {
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

func newCache() (*disk.Cache, error) {
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
