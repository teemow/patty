// Package source turns command line arguments into scan targets: local
// repositories, single GitHub repositories, or every repository of a user
// or organization.
package source

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/teemow/patty/internal/github"
)

// Target is one repository to scan.
type Target struct {
	// Display is the name shown in reports.
	Display string
	// Local is the path of a local repository; empty for GitHub targets.
	Local string
	// Repo describes a GitHub repository; nil for local targets.
	Repo *github.Repo
}

var githubURL = regexp.MustCompile(`^(?:https?://|git@|ssh://git@)github\.com[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$`)

// Resolve expands args into targets. An existing directory is scanned in
// place; owner/name and github.com URLs name one repository; a bare owner
// expands to all repositories of that user or organization.
func Resolve(ctx context.Context, client *github.Client, args []string, opts github.ListOptions) ([]Target, error) {
	var targets []Target
	for _, arg := range args {
		if info, err := os.Stat(arg); err == nil && info.IsDir() {
			targets = append(targets, Target{Display: arg, Local: arg})
			continue
		}
		owner, name, ok := parseGitHub(arg)
		if !ok {
			return nil, fmt.Errorf("%q is neither a directory, an owner/repo, a github.com URL nor an owner", arg)
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
		repos, err := client.ListRepos(ctx, owner, opts)
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
