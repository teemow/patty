# How patty works

## What patty finds that a clone does not

Everything git knows about a repository lives in its object database. Refs (branches, tags) are just entry points into it, and `git clone` copies only the objects reachable from the refs the server advertises. Secrets hide in the gaps:

| Where | How it gets there | Who still sees it |
|-------|-------------------|-------------------|
| Deleted files, old branches | Ordinary history | Everyone with a clone; `git log --all` finds it |
| `refs/pull/*/head` and `/merge` | Every pull request ever opened, from forks too | Anyone who fetches those refs from GitHub; not in a default clone |
| Force-pushed and deleted commits | `git commit --amend`, `rebase`, `push --force`, branch deletion | GitHub keeps serving them by SHA; the [activity feed](https://docs.github.com/en/rest/repos/repos#list-repository-activities) lists the SHAs |
| Reflog, stashes, dangling objects | Local rewrites | Whoever has that working copy -- often the very machine an incident investigation runs on |
| Commit messages and tag messages | `git commit -m "token is ghp_..."` | Everyone; file scanners skip them |

patty covers all five rows:

1. **Mirror, not clone.** `git clone --mirror` fetches every ref the server advertises. On GitHub that includes `refs/pull/*`, so the history of every pull request comes along.
2. **Fetch what was rewritten.** The repository activity feed names the `before` SHA of every force push and branch deletion. patty fetches those commits by SHA -- GitHub serves any object it still holds -- and marks them as *orphaned* in the report, with the ref, date and actor of the rewrite. Commits GitHub has since pruned are counted as unavailable.
3. **Scan objects, not diffs.** `git cat-file --batch-all-objects` lists every blob, commit and tag in the database, reachable or not. Each is read once through parallel `git cat-file --batch` streams and handed to the detector. A rewritten history shares nearly all of its blobs with the original, so this is also why it is fast: a file that appears in 10,000 commits is scanned once.
4. **Attribute afterwards.** Only for objects that contain a token does patty look up the path (`git rev-list --objects`, once for reachable history and once for the orphaned commits), the oldest commit that introduced the object (`git log --find-object`), and the refs that still contain that commit (`git for-each-ref --contains`).

Local targets skip steps 1 and 2 and scan the object database as it is, reflog and stashes included.

## Detection

Detection, verification and revocation are organised per **provider**; each provider knows its own token formats, its API and where its tools keep tokens on a developer machine. patty ships with three:

| Provider | Prefix | Kind | Verified offline |
|----------|--------|------|------------------|
| GitHub | `ghp_` | personal access token (classic) | checksum |
| GitHub | `gho_` | OAuth access token | checksum |
| GitHub | `ghu_` | GitHub App user-to-server token | checksum |
| GitHub | `ghs_` | GitHub App installation token | checksum |
| GitHub | `ghr_` | GitHub App refresh token | checksum |
| GitHub | `github_pat_` | fine-grained personal access token | shape only |
| Slack | `xoxb-` | bot token | shape; names team and bot id |
| Slack | `xoxp-` | user token | shape; names team and user id |
| Slack | `xapp-1-` | app-level token | shape; names the app id |
| Slack | `xoxe-1-` | refresh token | shape only |
| Slack | `xoxe.xoxb-1-`, `xoxe.xoxp-1-` | configuration or rotating access token | shape only |
| Slack | `https://hooks.slack.com/services/`, `/workflows/`, `/triggers/` | incoming webhook URL | shape; names the team id |
| AWS | `AKIA` (also `ABIA`, `ACCA`, `A3T…`) | access key | shape; names the account id, pairs the secret found next to it |
| AWS | `ASIA` | temporary access key (STS) | shape; names the account id, pairs the secret and session token found next to it |

The classic GitHub families carry a [CRC32 checksum](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) in their last six characters, Base62-encoded. patty recomputes it: a string with the right prefix and length but a wrong checksum is not a token and is not reported. That removes the false positives a pure regex match has to live with -- a `ghp_` followed by 36 random alphanumerics in a test fixture, a hash, a minified bundle -- and is why the report needs no allow-list to stay readable. The fine-grained format does not have a documented checksum, so it is matched on its shape (`github_pat_`, 22 characters, `_`, 59 characters) and best confirmed with `--verify`.

Slack tokens have no checksum, but their shapes are strict: fixed-length numeric ids separated by dashes and a secret of a fixed length and alphabet, and a webhook URL has a fixed host, route and id layout. The numeric ids are the workspace (team) and the user or bot the token was issued to, so the report can attribute a Slack token without contacting Slack.

An AWS access key id is a four-character prefix and sixteen characters of the base32 alphabet (`A-Z`, `2-7`), so it never contains `0`, `1`, `8` or `9`. The base32 body encodes the id of the account the key was issued in, which patty decodes offline and shows as *account 123456789012*. A key id is only usable together with its secret access key, forty characters of base64, so patty looks for one in the same object: preferring a run named by `aws_secret_access_key`, `SecretAccessKey` or `secret_key`, then one on the key's own line or the line after it, then the closest one, and for a temporary key also the session token that goes with it. The report says whether it found a *key pair* or a *key id only*. The secret is what makes a leak exploitable, but it is never shown, fingerprinted or written to the JSON; the key id is the credential's name throughout.

The scan itself is a handful of substring searches per object (`gh`, `github_pat_`, `xoxb-`, `xoxp-`, `xapp-1-`, `xoxe`, `https://hooks.slack.com/`, `AKIA`, `ASIA`, `ABIA`, `ACCA`, `A3T`) with an exact shape and, where there is one, checksum check at each candidate; only an object that holds an AWS key id is searched for its secret. It runs at about 1 GB/s per core; `git` decompressing objects is the bottleneck, which is why the readers run in parallel.

## Compared with gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks) is a general secret scanner with more than 200 rules, allow-lists, baselines and CI integrations. patty is a narrow tool with one question: *is there a GitHub, Slack or AWS credential anywhere in this repository's past?* Where they overlap the differences are:

| | gitleaks `git` | patty |
|---|---|---|
| History covered | commits reachable from refs (`git log -p --all`) | every object in the database, plus `refs/pull/*` and force-pushed or deleted commits fetched from GitHub |
| Unit of work | each commit's diff; content that appears in many commits is scanned as often | each object once |
| GitHub, Slack and AWS credentials | regex + entropy | exact shape + checksum where the format has one, offline attribution, optional live check |
| Where it points | commit and file of each occurrence | oldest introducing commit, all refs that still contain it, and how orphaned commits went unreachable |
| Scope | one repository or directory | any number of repositories, whole owners, with a disk budget |
| Everything else | Stripe, private keys, ... | GitHub, Slack and AWS credentials only |

Use both: gitleaks in CI on every push, patty when you want to know what is already out there.

## Disk budget

Mirroring an organization can mean tens of gigabytes. patty never fills a drive:

- Before cloning it checks the repository size GitHub reports (times three, which is what a mirror with pull request refs has been measured at) against the remaining **`--max-disk`** budget and the drive's free space minus **`--min-free`**. A repository that does not fit is **skipped** with a message, not cloned halfway.
- Mirrors are removed as soon as their scan finishes, unless **`--keep`** is set. With `--keep`, the least recently used mirrors are evicted when the budget runs out, and a re-run of a kept mirror is a `git fetch` rather than a fresh clone.
- Mirrors are bare: no working tree is ever checked out.
- Objects larger than **`--max-object`** are skipped and counted; a token in a 200 MB binary is not what patty is for.

`patty cache` shows what is kept, `patty cache clean` removes it.
