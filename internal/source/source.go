// Package source turns command line arguments into scan targets: local
// repositories, directories and files, single GitHub repositories, or every
// repository of a user or organization.
package source

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/teemow/patty/internal/github"
	"github.com/teemow/patty/internal/gitrepo"
)

// Target is one repository or file tree to scan.
type Target struct {
	// Display is the name shown in reports.
	Display string
	// Local is the path of a local repository; empty for GitHub targets
	// and for file trees without a repository behind them.
	Local string
	// Dir is the path of a directory, or a single file, whose files are
	// scanned as they are on disk. It is set on its own for a directory
	// that is not a repository, and next to Local when the working tree of
	// a repository is scanned as well as its object database.
	Dir string
	// Repo describes a GitHub repository; nil for local targets.
	Repo *github.Repo
}

// Files reports whether the target is scanned as files on disk only, with
// no repository history behind it.
func (t Target) Files() bool {
	return t.Dir != "" && t.Local == ""
}

// Options tune how arguments are resolved.
type Options struct {
	github.ListOptions
	// Files scans the working tree of a local repository as well as its
	// object database, so untracked and ignored files are covered. A
	// directory that is not a repository is always scanned as files.
	Files bool
}

var githubURL = regexp.MustCompile(`^(?:https?://|git@|ssh://git@)github\.com[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$`)

// Resolve expands args into targets. An existing path is scanned in place:
// a repository through its object database, any other directory or a
// single file as files on disk. owner/name and github.com URLs name one
// repository; a bare owner expands to all repositories of that user or
// organization.
func Resolve(ctx context.Context, client *github.Client, args []string, opts Options) ([]Target, error) {
	var targets []Target
	for _, arg := range args {
		if info, err := os.Stat(arg); err == nil {
			targets = append(targets, local(ctx, arg, info, opts.Files))
			continue
		}
		owner, name, ok := parseGitHub(arg)
		if !ok {
			return nil, fmt.Errorf("%q is neither a path, an owner/repo, a github.com URL nor an owner", arg)
		}
		if client == nil {
			return nil, fmt.Errorf("%q needs GitHub access", arg)
		}
		if name != "" {
			repo, err := client.Repo(ctx, owner, name)
			if err != nil {
				return nil, err
			}
			targets = append(targets, fromRepo(repo))
			continue
		}
		repos, err := client.ListRepos(ctx, owner, opts.ListOptions)
		if err != nil {
			return nil, err
		}
		if len(repos) == 0 {
			return nil, fmt.Errorf("%s has no repositories to scan", owner)
		}
		for _, r := range repos {
			targets = append(targets, fromRepo(r))
		}
	}
	return targets, nil
}

// local resolves an existing path: a single file and a directory that is
// not inside a repository are file trees, a repository is scanned through
// its object database and, with files, its working tree too.
func local(ctx context.Context, path string, info fs.FileInfo, files bool) Target {
	t := Target{Display: path}
	if !info.IsDir() {
		t.Dir = path
		return t
	}
	if _, err := gitrepo.Open(ctx, path); err != nil {
		t.Dir = path
		return t
	}
	t.Local = path
	if files {
		t.Dir = path
	}
	return t
}

func fromRepo(r github.Repo) Target {
	return Target{Display: r.FullName(), Repo: &r}
}

func parseGitHub(arg string) (owner, name string, ok bool) {
	if m := githubURL.FindStringSubmatch(arg); m != nil {
		return m[1], m[2], true
	}
	if strings.ContainsAny(arg, " \t:@") {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(arg, "/"), "/")
	switch len(parts) {
	case 1:
		return parts[0], "", parts[0] != ""
	case 2:
		return parts[0], strings.TrimSuffix(parts[1], ".git"), parts[0] != "" && parts[1] != ""
	}
	return "", "", false
}
