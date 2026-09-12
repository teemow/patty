# Reading the report

Each distinct token is listed once, with every place it was found across all scanned repositories:

```
3 GitHub tokens found (2 active) in 108 repositories, 82473 objects, 1.5 GiB

● ACTIVE     github-oauth             gho_g5F3Ab12…yH3p  fp 3bb5f28f2ce5be41  user jane, scopes: gist, read:org, repo  issued to GitHub CLI
    acme/dotfiles  .config/gh/hosts.yml:6  2c10f8f4 2025-04-15 Jane Doe · initial commit
                   not on any branch or tag, only reachable through pull request refs: PR #1, PR #10, +11 more
    ↳ revoke   at https://github.com/settings/applications under GitHub CLI; or run again with --revoke
    ↳ local    still configured in ~/.git-credentials; replace it there after revoking
    ↳ history  acme/dotfiles: only in pull request refs (GitHub Support has to purge those) · forks made in the meantime keep their own copy

● ACTIVE     github-pat               ghp_2O6PWxYz…k3Lq  fp b492588d8d3ffbbb  user acme-bot, scopes: repo, workflow
    acme/dotfiles  .config/hub:4  2c10f8f4 2025-04-15 Jane Doe · initial commit
                   not on any branch or tag, only reachable through pull request refs: PR #1, PR #10, +11 more
    acme/lab       trials/run-7/messages.json:107  4048b6e8 2026-05-29 Jane Doe · record trial output
                   on main, +405 more
    ↳ revoke   at https://github.com/settings/tokens; or run again with --revoke
    ↳ local    still configured in ~/.config/hub; replace it there after revoking
    ↳ history  acme/dotfiles: only in pull request refs (GitHub Support has to purge those) · acme/lab: in branch history (rewrite with git filter-repo, then force-push) · forks made in the meantime keep their own copy

● revoked    github-pat               ghp_jtP7Ab12…9zXy  fp 58b0d6ffe3821055
    acme/infra     cluster/apps/secret.sops.yaml:8  96a9ac2e 2026-01-05 Jane Doe · add training app
                   orphaned: no branch, tag or PR reaches this commit · force-pushed away from main on 2026-01-06 by jane
```

The first line of each token says what it is. With `--verify`, an active token shows the user it belongs to and its scopes, the application it was issued to when GitHub reports one (GitHub CLI, Copilot, Desktop, VS Code, or the raw OAuth client id), and its expiry date if it has one.

The second line of each location says how reachable the commit still is:

- **on main, v1.2, PR #7** -- ordinary history; the token is in the repository as anyone clones it. `--all-refs` lists all of them instead of `+405 more`.
- **only reachable through pull request refs** -- someone rewrote the branch to remove it, but the pull request that carried it still serves the old commits (`refs/pull/N/head`), and so does every fork that was made in between
- **orphaned** -- no ref reaches the commit anymore; GitHub still serves it by SHA to anyone who has it (the activity feed, an old notification email, a CI log). When patty knows how it went unreachable, it says so: *force-pushed away from main on 2026-01-06 by jane*

The `↳` lines under a token that GitHub has not rejected yet say what to do about it:

- **revoke** -- the settings page where its owner revokes it by hand, or `--revoke` to let patty do it
- **local** -- the token is also configured on the machine running patty: `~/.config/gh/hosts.yml`, `~/.config/hub`, Copilot's `hosts.json`, `~/.git-credentials`, `~/.netrc`, `.env` files in the working directory, `GITHUB_TOKEN`/`GH_TOKEN`, or whatever `gh auth token` returns. Only fingerprints are compared; the values never leave those files. Replace it there, or the next commit leaks it again.
- **history** -- per repository, whether the token sits in branch history (yours to rewrite with [`git filter-repo`](https://github.com/newren/git-filter-repo) and force-push), only in pull request refs or in orphaned commits (only [GitHub Support](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) can purge those)

Active tokens come first. Revoke them before anything else.

## Revoking

GitHub runs an unauthenticated endpoint for reporting leaked credentials, `POST /credentials/revoke`. Anyone who finds a token can submit it; GitHub revokes it and emails the owner. It accepts personal access tokens (classic and fine-grained), OAuth tokens, and GitHub App user-to-server and refresh tokens -- everything patty finds except installation tokens (`ghs_`), which expire within an hour anyway.

```bash
patty acme --revoke                       # scan, verify, list the active tokens, ask, revoke
patty acme --revoke --yes                 # the same without the question
patty acme --revoke --ignore b492588d…    # leave one token alone
patty revoke < tokens.txt                 # tokens you already have, one per line (or anywhere in the text)
```

`--revoke` implies `--verify` and only ever submits tokens GitHub just confirmed as active. It shows what it is about to revoke and asks; without a terminal it refuses unless `--yes` is given, so a cron job cannot revoke by accident. Two side effects are called out in that list, because they are easy to miss:

- Revoking an OAuth or GitHub App token (`gho_`, `ghu_`, `ghr_`) revokes the **whole authorization** of that application. Every token it holds for the user dies, including the one in use right now: revoke an old GitHub CLI token and `gh` is logged out on every machine until `gh auth login` is run again.
- A token that is still configured on this machine (the *local* line) stops working for that tool the moment it is revoked. Have the replacement ready.

Afterwards each token is checked again: GitHub processes revocations asynchronously, so a token may still answer as *pending* for a moment. In the report and the JSON (`"revocation": "revoked" | "pending"`) that is recorded per token.

## Fingerprints

Every token is shown with a **fingerprint** (`fp b492588d8d3ffbbb`): the first 16 hex characters of its SHA-256. It identifies a token in logs and reports without revealing it, and `--ignore b492588d8d3ffbbb,58b0d6ffe3821055` keeps tokens you have already dealt with out of future reports.

## What leaves your machine

`--verify` sends each found token to `GET /user` (or `GET /installation/repositories` for app installation tokens) to see whether GitHub still accepts it. `--revoke` and `patty revoke` send tokens to `POST /credentials/revoke`. Nothing else ever leaves your machine; the tokens patty finds are not sent anywhere unless you ask for that.
