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

The first line of each credential says what it is; the kind names the provider (`github-…`, `slack-…`, `aws-…`, `anthropic-…`, `openai-…`). What the token's own shape reveals about its owner comes next: a Slack token names the workspace and the user or bot it was issued to, a webhook URL the workspace; an AWS key id names the account it was issued in, and whether its secret was found next to it (*key pair*) or not (*key id only, secret not found nearby*). With `--verify`, an active token shows what its provider says about it: for GitHub the user and scopes, the application it was issued to when GitHub reports one (GitHub CLI, Copilot, Desktop, VS Code, or the raw OAuth client id), and its expiry date if it has one; for Slack the workspace, the user or bot, and the scopes; for AWS the ARN of the user or role session the key belongs to. A key id found without its secret cannot be verified and is reported as *unverifiable*: treat it as live.

Anthropic and OpenAI say nothing about a key that merely authenticates, so an active key shows *accepted by the API*, for OpenAI with the organization and project the API names in its response headers, and an Anthropic admin key with the organization it administers. With `ANTHROPIC_ADMIN_KEY` or `OPENAI_ADMIN_KEY` set (see the README's Setup), a key of that organization is also named the way its Console lists it: *key CI deploy, workspace wrkspc_…, created by user user_…* or *key deploy in project Beta, owned by service account ci*; a key that is not in the organization's list stays at *accepted by the API*. An Anthropic key that authenticates but may not list models (*accepted, but not allowed to list models*) is live all the same. A 429 from OpenAI is reported as *unknown*: a key whose quota is exhausted answers exactly like a rate-limited one, and is still live. Anthropic OAuth refresh tokens (`sk-ant-ort01-`) are *unverifiable*: they are exchanged through the OAuth client, not usable against the API.

An age identity names its public key (*recipient age1…*), which is what a `.sops.yaml` lists; a PGP private key names its fingerprint and user id and says whether it is *passphrase-protected*. Neither has an issuer to ask, so `--verify` reports both as *unverifiable*: an identity is valid by construction, the checksum or the key packets said so when it was found, and the *decrypts* line below is what tells how much it matters.

The second line of each location says how reachable the commit still is:

- **on main, v1.2, PR #7** -- ordinary history; the token is in the repository as anyone clones it. `--all-refs` lists all of them instead of `+405 more`.
- **only reachable through pull request refs** -- someone rewrote the branch to remove it, but the pull request that carried it still serves the old commits (`refs/pull/N/head`), and so does every fork that was made in between
- **orphaned** -- no ref reaches the commit anymore; GitHub still serves it by SHA to anyone who has it (the activity feed, an old notification email, a CI log). When patty knows how it went unreachable, it says so: *force-pushed away from main on 2026-01-06 by jane*

The `↳` lines under a credential its provider has not rejected yet say what to do about it:

- **decrypts** -- for an age identity or PGP key: the repositories and files among the scanned ones that list its public key or fingerprint as a sops recipient, `acme/infra: 42 files (clusters/prod/secrets.sops.yaml, +41 more) · acme/app: 3 files (…)`. That is what the leak is worth: everything in those files, in every commit that holds them, is readable to whoever has the key. When nothing matches the line says so; the key may still decrypt files in repositories that were not scanned.
- **revoke** -- the settings page where its owner revokes it by hand, or `--revoke` to let patty do it. A key nothing can revoke gets the rotation procedure instead: remove the recipient from `.sops.yaml`, run `sops updatekeys` on every affected file, then `sops rotate -i` on each so the data key changes too, and for a PGP key publish a revocation certificate. Rotation protects future commits only. Every commit already encrypted to the old recipient stays decryptable by whoever holds the key, and only rewriting history (the *history* line) helps with those.
- **local** -- the token is also configured on the machine running patty. For GitHub: `~/.config/gh/hosts.yml`, `~/.config/hub`, Copilot's `hosts.json`, `~/.git-credentials`, `~/.netrc`, `GITHUB_TOKEN`/`GH_TOKEN`, or whatever `gh auth token` returns. For Slack: `~/.slack/credentials.json` and `SLACK_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_USER_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_WEBHOOK_URL`. For AWS: `~/.aws/credentials`, `~/.aws/config`, `~/.s3cfg`, rclone's `rclone.conf` and `AWS_ACCESS_KEY_ID`. For Anthropic: `ANTHROPIC_API_KEY`, `ANTHROPIC_ADMIN_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, Claude Code's `~/.claude/.credentials.json` and `~/.claude.json`, and opencode's `~/.config/opencode/auth.json`. For OpenAI: `OPENAI_API_KEY`, `OPENAI_ADMIN_KEY`, Codex's `~/.codex/auth.json` (which mostly holds a sign-in, not a key; only a key found there is compared) and opencode's `auth.json`. For sops: `~/.config/sops/age/keys.txt`, `SOPS_AGE_KEY`, and the file `SOPS_AGE_KEY_FILE` points at. PGP keys live in the GnuPG keyring, which is not a text file and is not read; `gpg --list-secret-keys` shows whether a reported fingerprint is on this machine. `.env` files in the working directory are checked for all of them. Only fingerprints of key ids and tokens are compared; the values never leave those files. Replace it there, or the next commit leaks it again.
- **history** -- per repository, whether the token sits in branch history (yours to rewrite with [`git filter-repo`](https://github.com/newren/git-filter-repo) and force-push), only in pull request refs or in orphaned commits (only [GitHub Support](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) can purge those)
- **audit** -- for providers that keep a usage log, where to look for what the credential was used for while it was exposed. For AWS that is CloudTrail, from the commit date on; for Anthropic and OpenAI the usage page of their console, filtered by key. Both are GitHub secret scanning partners and disable keys found in public repositories on their own (OpenAI also emails the owner), so a key from public history is probably already dead; `--verify` confirms. This line stays even for a key that is dead by now.

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

### AWS

AWS has no endpoint for reporting a leaked key, so `--revoke` does the next best thing: it deactivates the key through [`iam:UpdateAccessKey`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html), signed with the key itself, on the IAM user the key belongs to. That works when the key pair is complete and its user may manage its own access keys; when it may not, the report says *this key is not allowed to deactivate itself* and points at the IAM console. A key that belongs to a role session or the root user, and any temporary key, cannot be handled this way. The key is set to *Inactive*, which its owner can undo; deleting it for good (`aws iam delete-access-key`) is left to them. There is no dry run.

By hand: IAM console → Users → the user → Security credentials → deactivate, then delete the key; or `aws iam update-access-key --access-key-id <id> --status Inactive` followed by `aws iam delete-access-key --access-key-id <id>`. Then check CloudTrail for what the key did since the commit that leaked it. A key that lands in a public GitHub repository is usually noticed by AWS within minutes, which attaches the `AWSCompromisedKeyQuarantine` policy to the user: that limits what the key may do (no new users, roles or instances) but does not deactivate it. Temporary keys (`ASIA`) expire on their own within hours; find and stop the process or role session that minted them, or use *Revoke sessions* on the role.

### Slack

Slack tokens are revoked with [`auth.revoke`](https://api.slack.com/methods/auth.revoke), authenticated with the token itself; Slack does not notify anyone. Before asking for confirmation patty calls the method in its test mode (`test=1`), which answers exactly as the real call would without revoking anything, and shows that answer under each token. Revoking a **bot token** deactivates the app's installation in that workspace: the app has to be reinstalled there to get a new token. Revoking a **user token** removes that user's authorization of the app in that workspace. Neither deletes the app, touches its installations in other workspaces, or deactivates its **app-level tokens**, **configuration tokens** or **incoming webhooks**; those are removed in the app's settings, and the report points there. Refresh tokens are accepted by `auth.revoke` but cannot be verified without rotating them, so `--revoke` never submits one; `patty revoke` does when given one.

### Anthropic

Anthropic's API cannot revoke a key by itself, and its Admin API only manages API keys, not admin keys or OAuth tokens. With `ANTHROPIC_ADMIN_KEY` set to an [Admin API key](https://console.anthropic.com/settings/admin-keys) of the organization, `--revoke` lists the organization's API keys (`GET /v1/organizations/api_keys`, paginated), matches each leaked key against the partial hint Anthropic shows for every key (`sk-ant-api03-R2D…igAA`: the characters before and after the ellipsis are compared with the leaked value), and sets the one match to *inactive* (`POST /v1/organizations/api_keys/{id}`). Before asking for confirmation patty does the listing and matching only, and shows the result under each key. A key no hint matches belongs to another organization and is reported as *not in this organization*, not as revoked; a hint that fits more than one key is reported too, and nothing is touched. Without an admin key, `--revoke` says so and the report points at the [Console](https://console.anthropic.com/settings/keys). An inactive key can be reactivated in the Console; archiving it for good is left to the owner.

Admin keys are managed only in the Console. OAuth tokens belong to a Claude Code sign-in: run `claude auth logout` on the machine that signed in, or sign the session out on claude.ai; the access token expires on its own within hours, the refresh token does not.

### OpenAI

OpenAI's API cannot revoke a key by itself either. With `OPENAI_ADMIN_KEY` set to an [admin key](https://platform.openai.com/settings/organization/admin-keys) of the organization, `--revoke` finds a leaked admin key in the organization's admin key list (`GET /v1/organization/admin_api_keys`) and a leaked project or service account key in the key lists of every project, archived ones included (`GET /v1/organization/projects`, then `GET /v1/organization/projects/{id}/api_keys`), matching each against the redacted value OpenAI shows for every key (`sk-abc...def`), and deletes the one match (`DELETE` on the same path). As with Anthropic, the dry run before the confirmation lists and matches only; a key no entry matches is *not in this organization*; an ambiguous match deletes nothing. OpenAI may refuse to delete a service account's key on its own, in which case deleting the service account under the project's settings removes it. Deletion is final. Legacy user keys (`sk-` and twenty characters on either side of the marker) are not listed by the Admin API and are revoked under the owner's [API keys](https://platform.openai.com/api-keys).

## Fingerprints

Every credential is shown with a **fingerprint** (`fp b492588d8d3ffbbb`): the first 16 hex characters of its SHA-256. It identifies a token in logs and reports without revealing it, and `--ignore b492588d8d3ffbbb,58b0d6ffe3821055` keeps tokens you have already dealt with out of future reports.

## What leaves your machine

`--verify` sends each found credential to its provider, once: GitHub tokens to `GET /user` (or `GET /installation/repositories` for app installation tokens), Slack tokens to `POST auth.test`, and Slack webhook URLs receive one `POST` with an empty JSON object, which Slack rejects without posting anything. An AWS key pair signs one `sts:GetCallerIdentity` call, which needs no permission and is not retried; it is recorded in CloudTrail in the key owner's account, so the owner can see that the key was checked. A key id without its secret is not sent anywhere. `--revoke` and `patty revoke` send GitHub tokens to `POST /credentials/revoke`, Slack tokens to `POST auth.revoke`, first in test mode and then, after confirmation, for real, and AWS key pairs sign one more `sts:GetCallerIdentity` and one `iam:UpdateAccessKey`. Anthropic API keys and OAuth access tokens make one `GET /v1/models` (with the `anthropic-beta: oauth-2025-04-20` header for OAuth tokens, which the API requires), Anthropic admin keys one `GET /v1/organizations/me`; OpenAI keys make one `GET /v1/models`, OpenAI admin keys one `GET /v1/organization/admin_api_keys`. When `ANTHROPIC_ADMIN_KEY` or `OPENAI_ADMIN_KEY` is set, the organization's key list is fetched once per run with that key so the report can name the leaked keys; the leaked keys themselves are compared locally against the hints in that list and are not sent to the Admin API. `--revoke` then sends one status change or deletion per matched key, with the admin key. Age identities, PGP keys and Anthropic refresh tokens are never sent anywhere, with or without `--verify`: there is no one to ask. Nothing else ever leaves your machine; the credentials patty finds are not sent anywhere unless you ask for that.
