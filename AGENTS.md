# patty: notes for agents

patty finds every credential in a repository's history and says what to do about it. [CONTRIBUTING.md](CONTRIBUTING.md) is the playbook: the checks to run before pushing, the rules every change keeps, the checklist for adding a provider, how to verify a release and how to debug a hung scan. [docs/how-it-works.md](docs/how-it-works.md) and [docs/report.md](docs/report.md) describe the behaviour the code must match.

## This repository is public

Write every file, commit message, pull request title and body, and release note for a stranger:

- no employer, customer or colleague names, no internal hostnames (registries, dashboards, clusters), no links to private repositories or internal notes;
- nothing about anyone's machine or what is configured on it;
- no statement about the security posture of any organization.

When the reasoning behind a change comes from one organization's setup, keep that in the conversation and write the general case ("a platform team running Kubernetes on public clouds"). Before committing, grep the diff for the names and hosts of the organizations you work with. A leak here is not undone by a force-push: copies survive in pull request refs (only GitHub Support can purge those), in releases and in the Go module proxy.

## Git

- Pull requests are squash-merged on GitHub, so there is nothing to squash locally. Never squash with `git reset --soft origin/main` and a new commit: worktrees under `.claude/worktrees/` share their refs with every other checkout, `origin/main` may have moved under you, and the commit then silently reverts whatever landed in between. CI does not notice a revert.
- Before pushing, `git fetch origin` and check that `git diff --stat origin/main...HEAD` lists only the files you meant to change. After a merge, compare the merge commit's `--stat` with the same list before calling it done.
- Every merge to `main` cuts a release ([Releases](CONTRIBUTING.md#releases)); a merge is done when the released binary has been verified and run.
