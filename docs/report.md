# Reading the report

Each distinct credential is listed once, with every place it was found across all scanned repositories:

```
4 credentials found (3 active) in 108 repositories, 82473 objects, 1.5 GiB

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

● ACTIVE     slack-bot-token          xoxb-123…UvWx  fp 9c1e0a7b3d5f2e48  team 1234567890, bot 1234567890123  team acme, bot deploybot, scopes: chat:write  (shape match, no checksum)
    acme/ops       bot.env:2  7d3e1f0a 2026-03-02 Jane Doe · add deploy bot
                   on main
    ↳ revoke   at https://api.slack.com/apps; or run again with --revoke
    ↳ local    still configured in $SLACK_BOT_TOKEN; replace it there after revoking
    ↳ history  acme/ops: in branch history (rewrite with git filter-repo, then force-push) · forks made in the meantime keep their own copy

● revoked    github-pat               ghp_jtP7Ab12…9zXy  fp 58b0d6ffe3821055
    acme/infra     cluster/apps/secret.sops.yaml:8  96a9ac2e 2026-01-05 Jane Doe · add training app
                   orphaned: no branch, tag or PR reaches this commit · force-pushed away from main on 2026-01-06 by jane
```

The first line of each credential says what it is; the kind names the provider (`github-…`, `slack-…`). What the token's own shape reveals about its owner comes next: a Slack token names the workspace and the user or bot it was issued to, a webhook URL the workspace. With `--verify`, an active token shows what its provider says about it: for GitHub the user and scopes, the application it was issued to when GitHub reports one (GitHub CLI, Copilot, Desktop, VS Code, or the raw OAuth client id), and its expiry date if it has one; for Slack the workspace, the user or bot, and the scopes.

The second line of each location says how reachable the commit still is:

- **on main, v1.2, PR #7** -- ordinary history; the token is in the repository as anyone clones it. `--all-refs` lists all of them instead of `+405 more`.
- **only reachable through pull request refs** -- someone rewrote the branch to remove it, but the pull request that carried it still serves the old commits (`refs/pull/N/head`), and so does every fork that was made in between
- **orphaned** -- no ref reaches the commit anymore; GitHub still serves it by SHA to anyone who has it (the activity feed, an old notification email, a CI log). When patty knows how it went unreachable, it says so: *force-pushed away from main on 2026-01-06 by jane*

The `↳` lines under a credential its provider has not rejected yet say what to do about it:

- **revoke** -- the settings page where its owner revokes it by hand, or `--revoke` to let patty do it
- **local** -- the token is also configured on the machine running patty. For GitHub: `~/.config/gh/hosts.yml`, `~/.config/hub`, Copilot's `hosts.json`, `~/.git-credentials`, `~/.netrc`, `GITHUB_TOKEN`/`GH_TOKEN`, or whatever `gh auth token` returns. For Slack: `~/.slack/credentials.json` and `SLACK_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_USER_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_WEBHOOK_URL`. `.env` files in the working directory are checked for both. Only fingerprints are compared; the values never leave those files. Replace it there, or the next commit leaks it again.
- **history** -- per repository, whether the token sits in branch history (yours to rewrite with [`git filter-repo`](https://github.com/newren/git-filter-repo) and force-push), only in pull request refs or in orphaned commits (only [GitHub Support](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) can purge those)

Active credentials come first. Revoke them before anything else.

## Revoking

Each credential is revoked through its own provider's API. `--revoke` implies `--verify` and only ever submits credentials the provider just confirmed as active. It shows what it is about to revoke and asks; without a terminal it refuses unless `--yes` is given, so a cron job cannot revoke by accident.

```bash
patty acme --revoke                       # scan, verify, list the active credentials, ask, revoke
patty acme --revoke --yes                 # the same without the question
patty acme --revoke --ignore b492588d…    # leave one credential alone
patty revoke < tokens.txt                 # tokens you already have, one per line (or anywhere in the text)
```

Afterwards each credential is checked again and the outcome is recorded per credential in the report and the JSON (`"revocation": "revoked" | "pending"`).

### GitHub

GitHub runs an unauthenticated endpoint for reporting leaked credentials, `POST /credentials/revoke`. Anyone who finds a token can submit it; GitHub revokes it and emails the owner. It accepts personal access tokens (classic and fine-grained), OAuth tokens, and GitHub App user-to-server and refresh tokens -- everything patty finds except installation tokens (`ghs_`), which expire within an hour anyway.

Two side effects are called out in the confirmation list, because they are easy to miss:

- Revoking an OAuth or GitHub App token (`gho_`, `ghu_`, `ghr_`) revokes the **whole authorization** of that application. Every token it holds for the user dies, including the one in use right now: revoke an old GitHub CLI token and `gh` is logged out on every machine until `gh auth login` is run again.
- A token that is still configured on this machine (the *local* line) stops working for that tool the moment it is revoked. Have the replacement ready.

GitHub processes revocations asynchronously, so a token may still answer as *pending* in the follow-up check for a moment.

### Slack

Slack tokens are revoked with [`auth.revoke`](https://api.slack.com/methods/auth.revoke), authenticated with the token itself; Slack does not notify anyone. Before asking for confirmation patty calls the method in its test mode (`test=1`), which answers exactly as the real call would without revoking anything, and shows that answer under each token. Revoking a **bot token** deactivates the app's installation in that workspace: the app has to be reinstalled there to get a new token. Revoking a **user token** removes that user's authorization of the app in that workspace. Neither deletes the app, touches its installations in other workspaces, or deactivates its **app-level tokens**, **configuration tokens** or **incoming webhooks**; those are removed in the app's settings, and the report points there. Refresh tokens are accepted by `auth.revoke` but cannot be verified without rotating them, so `--revoke` never submits one; `patty revoke` does when given one.

## Fingerprints

Every credential is shown with a **fingerprint** (`fp b492588d8d3ffbbb`): the first 16 hex characters of its SHA-256. It identifies a token in logs and reports without revealing it, and `--ignore b492588d8d3ffbbb,58b0d6ffe3821055` keeps tokens you have already dealt with out of future reports.

## What leaves your machine

`--verify` sends each found credential to its provider, once: GitHub tokens to `GET /user` (or `GET /installation/repositories` for app installation tokens), Slack tokens to `POST auth.test`, and Slack webhook URLs receive one `POST` with an empty JSON object, which Slack rejects without posting anything. `--revoke` and `patty revoke` send GitHub tokens to `POST /credentials/revoke` and Slack tokens to `POST auth.revoke`, first in test mode and then, after confirmation, for real. Nothing else ever leaves your machine; the credentials patty finds are not sent anywhere unless you ask for that.
