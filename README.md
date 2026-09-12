<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.png">
    <img alt="patty" src="assets/logo-light.png" height="160">
  </picture>
</p>
<h1 align="center">patty</h1>
<p align="center">
  Finds leaked GitHub tokens in every corner of a repository's history.<br>
  Marge's sister. Works at the DMV. Checks everyone's credentials.
</p>

---

A token that was committed once is in the repository forever -- even after the file was deleted, the commit amended, the branch force-pushed or the pull request closed. A normal clone does not show most of that history, and a scanner that walks `git log --all` never sees it. patty does: it mirrors the whole object database, pulls in what GitHub still holds but no ref points at anymore, and scans every object once.

It is fast enough to point at an entire organization. 210,000 objects and 6.7 GiB of content of [prometheus/prometheus](https://github.com/prometheus/prometheus) scan in about two seconds; the wall clock is the clone.

## Install

### From GitHub releases

Download the latest binary from the [releases page](https://github.com/teemow/patty/releases) for your platform (Linux, macOS, Windows; amd64 and arm64).

### From source

```bash
go install github.com/teemow/patty@latest
```

Or clone and build locally:

```bash
git clone https://github.com/teemow/patty.git
cd patty
make install
```

patty drives `git` on the command line, so git 2.30 or newer has to be on the `PATH`.

## Setup

For GitHub targets patty uses a token from `GITHUB_TOKEN`, `GH_TOKEN`, or the [gh CLI](https://cli.github.com/) (`gh auth token`), in that order. Without one it works anonymously: public repositories only, 60 API requests per hour.

**Classic token:** `repo` scope for private repositories, nothing for public ones.

**Fine-grained token:** select the repositories to scan, then grant:

| Permission | Access | Why |
|------------|--------|-----|
| Metadata | Read | List repositories, read sizes and the activity feed |
| Contents | Read | Clone private repositories |

`--verify` sends each found token to `GET /user` (or `GET /installation/repositories` for app installation tokens) to see whether GitHub still accepts it. Nothing else ever leaves your machine; the tokens patty finds are not sent anywhere unless you ask for that.

## Usage

### `patty [target...] [flags]`

A target is one of:

- a **local path** -- scanned in place, including anything only the reflog or a stash still knows about
- **`owner/repo`** or a **github.com URL** -- mirrored into the cache and scanned
- a bare **`owner`** (user or organization) -- every repository of that owner, private ones included when the token can see them

```bash
patty .                          # the repository you are in
patty acme/api acme/web          # two GitHub repositories
patty acme --verify              # everything acme owns; say which tokens are still live
patty acme --json > leaks.json   # machine-readable report
```

Exit code `0` means nothing was found, `1` that tokens were found, `2` that a target failed or was skipped and nothing was found.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--verify` | | `false` | Check each token against the GitHub API to tell **active** tokens from revoked ones |
| `--json` | | `false` | Print the report as JSON |
| `--show-secrets` | | `false` | Print full token values (the default shows `ghp_AbCdEfGh…WxYz`) |
| `--ignore` | | | Fingerprints to leave out of the report, comma-separated (see [Fingerprints](#fingerprints)) |
| `--keep` | | `false` | Keep mirrors in the cache after scanning; a re-run then only fetches what changed |
| `--cache-dir` | | `$XDG_CACHE_HOME/patty` | Where mirrors live |
| `--max-disk` | | `20G` | Total size the cache may occupy (see [Disk budget](#disk-budget)) |
| `--min-free` | | `2G` | Free space that must remain on the cache drive |
| `--max-object` | | `10M` | Skip objects larger than this |
| `--workers` | | CPU count | Parallel object readers per repository |
| `--parallel` | | `2` | Repositories processed at once |
| `--no-rewrites` | | `false` | Do not fetch force-pushed or deleted commits from the activity feed |
| `--activity-pages` | | `10` | Activity feed pages (100 events each) to read per repository and event type |
| `--include-forks` | | `false` | Include forks when expanding an owner |
| `--include-archived` | | `true` | Include archived repositories when expanding an owner |
| `--verbose` | `-v` | `false` | Print each phase (mirroring, activity feed, fetching, scanning) |

### Other commands

```bash
patty cache           # List mirrors kept with --keep and their size
patty cache clean     # Remove them
patty version         # Print the current version
patty self-update     # Update to the latest release
```

### Reading the report

Each distinct token is listed once, with every place it was found across all scanned repositories:

```
2 GitHub tokens found (1 active) in 108 repositories, 82473 objects, 1.5 GiB

● ACTIVE     github-pat               ghp_2O6PWxYz…k3Lq  fp b492588d8d3ffbbb  user acme-bot, scopes: repo, workflow
    acme/dotfiles  .config/hub:4  2c10f8f4 2025-04-15 Jane Doe · initial commit
                   not on any branch or tag, only reachable through pull request refs: PR #1, PR #10, +11 more
    acme/lab       trials/run-7/messages.json:107  4048b6e8 2026-05-29 Jane Doe · record trial output
                   on main, +405 more

● revoked    github-pat               ghp_jtP7Ab12…9zXy  fp 58b0d6ffe3821055
    acme/infra     cluster/apps/secret.sops.yaml:8  96a9ac2e 2026-01-05 Jane Doe · add training app
                   orphaned: no branch, tag or PR reaches this commit · force-pushed away from main on 2026-01-06 by jane
```

The second line of each location says how reachable the commit still is:

- **on main, v1.2, PR #7** -- ordinary history; the token is in the repository as anyone clones it
- **only reachable through pull request refs** -- someone rewrote the branch to remove it, but the pull request that carried it still serves the old commits (`refs/pull/N/head`), and so does every fork that was made in between
- **orphaned** -- no ref reaches the commit anymore; GitHub still serves it by SHA to anyone who has it (the activity feed, an old notification email, a CI log). When patty knows how it went unreachable, it says so: *force-pushed away from main on 2026-01-06 by jane*

Active tokens come first. Revoke them before anything else.

#### Fingerprints

Every token is shown with a **fingerprint** (`fp b492588d8d3ffbbb`): the first 16 hex characters of its SHA-256. It identifies a token in logs and reports without revealing it, and `--ignore b492588d8d3ffbbb,58b0d6ffe3821055` keeps tokens you have already dealt with out of future reports.

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

patty looks for GitHub's token families:

| Prefix | Kind | Verified offline |
|--------|------|------------------|
| `ghp_` | personal access token (classic) | checksum |
| `gho_` | OAuth access token | checksum |
| `ghu_` | GitHub App user-to-server token | checksum |
| `ghs_` | GitHub App installation token | checksum |
| `ghr_` | GitHub App refresh token | checksum |
| `github_pat_` | fine-grained personal access token | shape only |

The classic families carry a [CRC32 checksum](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) in their last six characters, Base62-encoded. patty recomputes it: a string with the right prefix and length but a wrong checksum is not a token and is not reported. That removes the false positives a pure regex match has to live with -- a `ghp_` followed by 36 random alphanumerics in a test fixture, a hash, a minified bundle -- and is why the report needs no allow-list to stay readable. The fine-grained format does not have a documented checksum, so it is matched on its shape (`github_pat_`, 22 characters, `_`, 59 characters) and best confirmed with `--verify`.

The scan itself is two substring searches per object (for `gh` and `github_pat_`) with an exact shape and checksum check at each candidate. It runs at about 1 GB/s per core; `git` decompressing objects is the bottleneck, which is why the readers run in parallel.

## Compared with gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks) is a general secret scanner with more than 200 rules, allow-lists, baselines and CI integrations. patty is a narrow tool with one question: *is there a GitHub token anywhere in this repository's past?* Where they overlap the differences are:

| | gitleaks `git` | patty |
|---|---|---|
| History covered | commits reachable from refs (`git log -p --all`) | every object in the database, plus `refs/pull/*` and force-pushed or deleted commits fetched from GitHub |
| Unit of work | each commit's diff; content that appears in many commits is scanned as often | each object once |
| GitHub tokens | regex + entropy | regex + checksum verification, optional live check |
| Where it points | commit and file of each occurrence | oldest introducing commit, all refs that still contain it, and how orphaned commits went unreachable |
| Scope | one repository or directory | any number of repositories, whole owners, with a disk budget |
| Everything else | AWS, Slack, Stripe, private keys, ... | GitHub tokens only |

Use both: gitleaks in CI on every push, patty when you want to know what is already out there.

## Disk budget

Mirroring an organization can mean tens of gigabytes. patty never fills a drive:

- Before cloning it checks the repository size GitHub reports (times three, which is what a mirror with pull request refs has been measured at) against the remaining **`--max-disk`** budget and the drive's free space minus **`--min-free`**. A repository that does not fit is **skipped** with a message, not cloned halfway.
- Mirrors are removed as soon as their scan finishes, unless **`--keep`** is set. With `--keep`, the least recently used mirrors are evicted when the budget runs out, and a re-run of a kept mirror is a `git fetch` rather than a fresh clone.
- Mirrors are bare: no working tree is ever checked out.
- Objects larger than **`--max-object`** are skipped and counted; a token in a 200 MB binary is not what patty is for.

`patty cache` shows what is kept, `patty cache clean` removes it.

## Development

```bash
make build          # Build the binary
make test           # Run tests (needs git on the PATH)
make lint           # Run golangci-lint
make logo           # Re-render assets/logo-*.png from the SVGs
make help           # Show all available targets
```

Test tokens are constructed at runtime from a random part plus a computed checksum, so no token-shaped string is committed to this repository -- its own gitleaks check would object.

## License

MIT -- see [LICENSE](LICENSE) for details.
