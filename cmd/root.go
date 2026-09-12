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

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/disk"
	"github.com/teemow/patty/internal/github"
	"github.com/teemow/patty/internal/gitrepo"
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
	jsonOut         bool
	showSecrets     bool
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
	Short: "Finds leaked GitHub tokens in every corner of a repository's history",
	Long: `Patty checks the credentials in your git history -- all of it.

A target is a local repository path, an owner/repo, a github.com URL, or a
bare owner (user or organization) to scan every repository of.

GitHub repositories are mirrored into a size-capped cache (all branches,
tags and pull request refs), extended with commits the repository activity
feed reports as force-pushed away or deleted, and every object in the
database is scanned -- reachable or not. Classic tokens are verified
offline against their built-in checksum; --verify asks GitHub whether a
token is still live.

Exit code 0 means nothing was found, 1 that tokens were found, 2 that a
target failed or was skipped and nothing was found.`,
	Args:          cobra.ArbitraryArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          run,
}

func init() {
	f := rootCmd.Flags()
	f.BoolVar(&opts.verify, "verify", false, "Check each token against the GitHub API to tell active tokens from revoked ones")
	f.BoolVar(&opts.jsonOut, "json", false, "Print results as JSON")
	f.BoolVar(&opts.showSecrets, "show-secrets", false, "Print full token values instead of redacted ones")
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
	f.StringSliceVar(&opts.ignore, "ignore", nil, "Token fingerprints to leave out of the report (comma-separated)")
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
	ropts := report.Options{Color: colors, ShowSecrets: opts.showSecrets}

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
	var verifier *detect.Verifier
	if opts.verify {
		verifier = detect.NewVerifier()
	}
	runOpts := scan.RunOptions{
		Options:       scan.Options{Workers: opts.workers, MaxObject: maxObject, Ignore: ignore, Verifier: verifier},
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
