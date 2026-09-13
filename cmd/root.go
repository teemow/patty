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
	ignore          []string
	verbose         bool
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
		Short: "Finds leaked GitHub, Slack, AWS, Anthropic, OpenAI, registry, Kubernetes and sops credentials and private keys in every corner of a repository's history",
		Long: `Patty checks the credentials in your git history -- all of it.

A target is a local repository path, an owner/repo, a github.com URL, or a
bare owner (user or organization) to scan every repository of.

GitHub repositories are mirrored into a size-capped cache (all branches,
tags and pull request refs), extended with commits the repository activity
feed reports as force-pushed away or deleted, and every object in the
database is scanned -- reachable or not. patty looks for GitHub tokens,
Slack tokens and webhooks, AWS access keys, Anthropic and OpenAI API keys,
the registry logins in Docker configs and pull secrets together with Docker
Hub and Quay tokens, the client certificates, tokens and logins of
kubeconfigs, Kubernetes service account tokens, SSH, TLS and cosign
private keys, and the age identities and PGP keys that decrypt sops
secrets; for those it also lists the sops files in the scanned
repositories that are encrypted to them, and for a private key the
certificates, authorized_keys files, image policies and GitHub accounts
that trust its public half. The values of
every Kubernetes Secret manifest are decoded and searched for all of the
above, and a Secret committed with plaintext values is reported on its own
(kind kubernetes-secret-manifest; --ignore takes kinds as well as
fingerprints). Classic GitHub tokens and age identities are verified
offline against their built-in checksum; --verify asks each provider
whether a credential is still live, and --revoke asks it to revoke the
live ones. Anthropic and OpenAI keys are revoked through the
organization's admin key, read from ANTHROPIC_ADMIN_KEY and
OPENAI_ADMIN_KEY. Kubernetes credentials are checked against the API
server their kubeconfig names, over https only and never on a private
network unless --verify-private-servers is given. An unencrypted SSH key
is offered to github.com once, with no command, after GitHub's published
host key fingerprints were checked.

Every credential comes with advice: where its owner revokes it, whether it
is still configured on this machine, and what its history needs.

Exit code 0 means nothing was found, 1 that credentials were found, 2 that
a target failed or was skipped and nothing was found.`,
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, opts, providers.Default())
		},
	}
	f := cmd.Flags()
	f.BoolVar(&opts.verify, "verify", false, "Check each credential against its provider's API to tell active ones from revoked ones")
	f.BoolVar(&opts.verifyPrivate, "verify-private-servers", false, "With --verify, also contact API servers on private, loopback or link-local addresses named in kubeconfigs")
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

// githubAccess returns the API client and git credentials for the targets
// that are not local directories, or nil when every target is one.
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

// needsGitHub reports whether any target is something other than a local
// directory.
func needsGitHub(args []string) bool {
	for _, a := range args {
		if info, err := os.Stat(a); err != nil || !info.IsDir() {
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
