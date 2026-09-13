// Package github talks to the GitHub API: repository discovery, size
// estimates for the disk budget and the activity feed that names commits a
// clone can no longer see.
package github

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-github/v91/github"
)

// Token returns the GitHub token from GITHUB_TOKEN, GH_TOKEN or the gh CLI,
// or "" when none is available. Public repositories work without one, but
// with a much lower API rate limit.
func Token() string {
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if t := strings.TrimSpace(os.Getenv(env)); t != "" {
			return t
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Client wraps the go-github client with the calls patty needs.
type Client struct {
	gh            *github.Client
	login         string
	authenticated bool
}

// NewClient returns a client; token may be empty for anonymous access.
func NewClient(token string) (*Client, error) {
	opts := []github.ClientOptionsFunc{github.WithUserAgent("patty")}
	if token != "" {
		opts = append(opts, github.WithAuthToken(token))
	}
	c, err := github.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	return &Client{gh: c, authenticated: token != ""}, nil
}

// Authenticated reports whether the client carries a token. Anonymous
// access is limited to sixty requests an hour, so optional lookups are
// skipped without one.
func (c *Client) Authenticated() bool { return c.authenticated }

// Contributors lists the logins of the repository's contributors, most
// commits first, at most limit of them. Anonymous contributors, which the
// API lists without a login, are left out.
func (c *Client) Contributors(ctx context.Context, owner, name string, limit int) ([]string, error) {
	contributors, _, err := c.gh.Repositories.ListContributors(ctx, owner, name, &github.ListContributorsOptions{ListOptions: github.ListOptions{PerPage: limit}})
	if err != nil {
		return nil, err
	}
	var logins []string
	for _, contributor := range contributors {
		if login := contributor.GetLogin(); login != "" {
			logins = append(logins, login)
		}
	}
	return logins, nil
}

// NewClientWithBaseURL is for tests against a fake API.
func NewClientWithBaseURL(baseURL string) *Client {
	base := strings.TrimSuffix(baseURL, "/") + "/"
	c, err := github.NewClient(github.WithURLs(&base, &base))
	if err != nil {
		panic(err)
	}
	return &Client{gh: c}
}

// Repo is what patty needs to know about a repository before cloning it.
type Repo struct {
	Owner    string
	Name     string
	SizeKB   int
	Fork     bool
	Archived bool
	Private  bool
	Empty    bool
}

// FullName returns owner/name.
func (r Repo) FullName() string { return r.Owner + "/" + r.Name }

// CloneURL returns the HTTPS clone URL.
func (r Repo) CloneURL() string { return "https://github.com/" + r.FullName() + ".git" }

// Repo fetches one repository.
func (c *Client) Repo(ctx context.Context, owner, name string) (Repo, error) {
	r, _, err := c.gh.Repositories.Get(ctx, owner, name)
	if err != nil {
		return Repo{}, fmt.Errorf("looking up %s/%s: %w", owner, name, err)
	}
	return toRepo(r), nil
}

// ListOptions filters ListRepos.
type ListOptions struct {
	IncludeForks    bool
	IncludeArchived bool
}

// ListRepos lists the repositories of a user or organization. For the
// authenticated user this includes private repositories.
func (c *Client) ListRepos(ctx context.Context, owner string, opts ListOptions) ([]Repo, error) {
	u, _, err := c.gh.Users.Get(ctx, owner)
	if err != nil {
		return nil, fmt.Errorf("looking up %s: %w", owner, err)
	}
	var (
		repos []Repo
		page  = 1
	)
	for {
		var (
			batch []*github.Repository
			resp  *github.Response
		)
		lo := github.ListOptions{PerPage: 100, Page: page}
		switch {
		case u.GetType() == "Organization":
			batch, resp, err = c.gh.Repositories.ListByOrg(ctx, owner, &github.RepositoryListByOrgOptions{Type: "all", ListOptions: lo})
		case c.isSelf(ctx, owner):
			batch, resp, err = c.gh.Repositories.ListByAuthenticatedUser(ctx, &github.RepositoryListByAuthenticatedUserOptions{Affiliation: "owner", ListOptions: lo})
		default:
			batch, resp, err = c.gh.Repositories.ListByUser(ctx, owner, &github.RepositoryListByUserOptions{Type: "owner", ListOptions: lo})
		}
		if err != nil {
			return nil, fmt.Errorf("listing repositories of %s: %w", owner, err)
		}
		for _, r := range batch {
			repo := toRepo(r)
			if (repo.Fork && !opts.IncludeForks) || (repo.Archived && !opts.IncludeArchived) || repo.Empty {
				continue
			}
			repos = append(repos, repo)
		}
		if resp.NextPage == 0 {
			return repos, nil
		}
		page = resp.NextPage
	}
}

func (c *Client) isSelf(ctx context.Context, owner string) bool {
	if c.login == "" {
		me, _, err := c.gh.Users.Get(ctx, "")
		if err != nil {
			c.login = "-"
		} else {
			c.login = me.GetLogin()
		}
	}
	return strings.EqualFold(c.login, owner)
}

func toRepo(r *github.Repository) Repo {
	owner, name, _ := strings.Cut(r.GetFullName(), "/")
	return Repo{
		Owner:    owner,
		Name:     name,
		SizeKB:   r.GetSize(),
		Fork:     r.GetFork(),
		Archived: r.GetArchived(),
		Private:  r.GetPrivate(),
		Empty:    r.GetSize() == 0 && r.GetDefaultBranch() == "",
	}
}

// Rewrite is a ref update that made commits unreachable on the server: a
// force push replaced Before with After, or a branch deletion removed Before.
type Rewrite struct {
	Before    string    `json:"before"`
	After     string    `json:"after,omitempty"`
	Ref       string    `json:"ref"`
	Type      string    `json:"type"`
	Actor     string    `json:"actor,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Describe renders the rewrite for a report.
func (r Rewrite) Describe() string {
	what := "force-pushed away from"
	if r.Type == "branch_deletion" {
		what = "deleted with"
	}
	s := fmt.Sprintf("%s %s on %s", what, strings.TrimPrefix(r.Ref, "refs/heads/"), r.Timestamp.UTC().Format("2006-01-02"))
	if r.Actor != "" {
		s += " by " + r.Actor
	}
	return s
}

type activity struct {
	Before       string    `json:"before"`
	After        string    `json:"after"`
	Ref          string    `json:"ref"`
	Timestamp    time.Time `json:"timestamp"`
	ActivityType string    `json:"activity_type"`
	Actor        *struct {
		Login string `json:"login"`
	} `json:"actor"`
}

// Rewrites reads the repository activity feed for force pushes and branch
// deletions. The Before SHA of each entry is a commit no clone fetches by
// default, but GitHub still serves it by SHA. maxPages caps the API calls
// per activity type (100 events per page).
func (c *Client) Rewrites(ctx context.Context, owner, name string, maxPages int) ([]Rewrite, error) {
	var out []Rewrite
	for _, typ := range []string{"force_push", "branch_deletion"} {
		after := ""
		for page := 0; page < maxPages; page++ {
			q := url.Values{"activity_type": {typ}, "per_page": {"100"}}
			if after != "" {
				q.Set("after", after)
			}
			req, err := c.gh.NewRequest(ctx, "GET", fmt.Sprintf("repos/%s/%s/activity?%s", owner, name, q.Encode()), nil)
			if err != nil {
				return nil, err
			}
			var batch []activity
			resp, err := c.gh.Do(req, &batch)
			if err != nil {
				return out, fmt.Errorf("reading activity of %s/%s: %w", owner, name, err)
			}
			for _, a := range batch {
				if a.Before == "" || strings.Trim(a.Before, "0") == "" {
					continue
				}
				rw := Rewrite{Before: a.Before, After: a.After, Ref: a.Ref, Type: a.ActivityType, Timestamp: a.Timestamp}
				if strings.Trim(rw.After, "0") == "" {
					rw.After = ""
				}
				if a.Actor != nil {
					rw.Actor = a.Actor.Login
				}
				out = append(out, rw)
			}
			if resp.After == "" || len(batch) == 0 {
				break
			}
			after = resp.After
		}
	}
	return out, nil
}
