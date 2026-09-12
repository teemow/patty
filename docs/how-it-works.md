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
