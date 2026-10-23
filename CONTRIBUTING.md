# Contributing

patty is a small Go program with one job: find every credential in a repository's history and say what to do about it. Changes that keep it that way are welcome: a new credential provider, a sharper shape check, a fact the report should state. Open an issue first for anything larger than a provider.

## Before you push

```bash
go build ./... && go vet ./... && golangci-lint run && go test -race ./...
gitleaks dir .
make docs      # regenerates the kinds table in docs/how-it-works.md; CI fails when it is stale
```

Tests need `git` on the `PATH`. `make help` lists every target. The lint gate in `.golangci.yml` caps cognitive complexity at 30 and flags duplicated blocks; split a function rather than exempting it.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `feat(detect): …`, `fix(report): …`, `docs: …`. The release workflow reads them to decide the next version, so a `feat` is a minor bump and a `fix` a patch. Pull requests are squash-merged, so the PR title is the commit that lands.

## Rules every change keeps

- **`Find` never contacts the network.** It reads the bytes it is handed and nothing else. Verification and revocation are separate methods and only run when the operator asks for them (`--verify`, `--revoke`).
- **No credential value is ever logged, printed or stored.** A finding is named by something that reveals nothing: a key id, a fingerprint, `host/username`, a `client_email/private_key_id`. Material that would make the finding usable (a secret access key, a password, a private key) goes into `Token.Secret`, which is never shown, fingerprinted or written to the JSON. Report output redacts `Token.Value` unless `--show-secrets` is given.
- **A candidate is a finding only when its shape says so.** Verify a built-in checksum where the format has one (classic GitHub tokens, age identities), parse what can be parsed (keys, certificates, JWTs, kubeconfigs), and require the companion a bare string is useless without (an AWS key id's secret, a Docker Hub token's username, an Azure secret's tenant and client). A shape that any hash could match is not a rule.
- **No token-shaped string is committed to this repository.** Test tokens are built at runtime: classic GitHub tokens from a random part plus a computed checksum, Slack tokens from their id groups and secret, AWS key ids from a prefix and a base32 body, Anthropic and OpenAI keys from a random body plus their fixed prefix, suffix or marker, Docker configs and pull secrets encoded on the fly, age identities, PGP keys and private keys freshly generated. Build even deliberately broken fixtures at runtime: gitleaks' `generic-api-key` rule trips on any `token`, `key` or `secret` keyword followed by a literal of ten characters or more, in a Go test as anywhere else, and CI runs gitleaks on every push. Keep the keyword and the value apart (`prefix + "AAAA.oops"`). Spelling `kind: Secret` in a Go test is fine: gitleaks' Secret-manifest rule only matches YAML paths.
- **The docs are part of the change.** The README and `patty --help` (the command's `Short` and `Long`) name no providers on purpose: one generic sentence, because a list of providers is unreadable at ten and goes stale with the eleventh. The detection table is the one canonical list, and the checklist below says which sections a provider owns.

## Adding a provider

A provider is one package under `internal/detect/<name>/`. `internal/detect/slack` is the smallest complete example; `internal/detect/privatekey` implements every correlation interface, `internal/detect/kubernetes` verifies against servers named in the scanned content, `internal/detect/grafana` and `internal/detect/gitlab` against instances the repository names anywhere, `internal/detect/anthropic` takes operator configuration, and `internal/detect/oci` (container registries) is handed the other providers because a registry password may be one of their credentials.

### Files

| File | Holds |
|------|-------|
| `provider.go` | The `Provider` type, `New()`, `Name()`, `Kinds()`, `LocalSources()`, and the `Kind` constants, whose strings name the provider and the family (`github-pat`, `age-identity`, `docker-hub-login`) |
| `token.go` | `Find(content []byte) []detect.Token`: the substring pre-check, the exact shape or parse, the companion search, and the offline attribution |
| `verify.go` | `Verify(ctx, tok) detect.Verification`: one request per credential, and the mapping of the provider's answers to a status |
| `revoke.go` | Only for a provider whose API revokes credentials: `Revoke(ctx, tokens) error` (usually a `detect.RevokeEach` loop, one request per credential) and `DryRunRevoke` when the API can rehearse. A provider nothing can revoke has no `revoke.go`; its `RevokeNote`s carry the owner's procedure |
| `*_test.go` | Next to each file. Shared runtime-built fixtures live in `fixtures_test.go`; HTTP behaviour is tested against `httptest.Server`, never the real API; command tests build a fresh command with `newRootCmd()` rather than sharing package state |

### The contract

`detect.Provider` in [internal/detect/provider.go](internal/detect/provider.go) is the whole contract; revocation is the optional `detect.Revoker` below:

1. **`Name()`** is what the report and the kinds table call the provider.
2. **`Kinds()`** describes every family as a `detect.KindInfo`: the `Description` a human reads, whether `--revoke` can handle it (`Revocable`), where the owner revokes it by hand (`RevokePage`), what to do when the API cannot (`RevokeNote`), a side effect of revoking that is easy to miss (`RevokeEffect`), where to look for what the credential did while exposed (`AuditNote`), and the flags that shape the report: `PublicValue` when `Token.Value` names the credential without revealing it, `Opaque` for material of no recognised shape, `UnlocksLabel` and `UnlocksNone` for the kinds of a `Correlator`. `patty kinds` renders all of it.
3. **`Find(content)`** returns every credential in `content` with `Offset` set; the registry fills in `Line`. Start with a cheap substring search, then check the exact shape at each candidate, then whatever the format allows offline: a checksum (`ChecksumVerified`), a parse, the companion found nearby, the attribution the shape alone gives (`Attribution`). The secret half goes into `Secret`, `Encrypted` marks passphrase-protected material. Every value of a Kubernetes Secret manifest is handed to `Find` decoded, so a provider does not decode base64 itself unless its own format nests it (a Docker config's `auth` entries).
4. **`Verify(ctx, tok)`** asks the provider once. Only its explicit invalid-credentials answer is `StatusRevoked`; a clean acceptance is `StatusActive` with a `Detail` that says what the credential reaches; anything else (network, rate limit, an unexpected status) is `StatusUnknown`, never a verdict. A kind that cannot be checked without side effects, or has no one to ask, is `StatusUnverifiable`.
5. **`LocalSources()`** names where tools keep this provider's credentials on a developer machine: environment variables holding a value (`Env`) or a file path (`EnvFiles`), files under `~/.config` (`ConfigFiles`) and under the home directory (`HomeFiles`), and commands that print a credential (`Commands`). Only fingerprints are compared against them.

### Optional interfaces

Implement these on the same type when the provider needs them; the registry discovers them with type assertions.

| Interface | When | Implemented by |
|-----------|------|----------------|
| `Revoker` (`Revoke`) | The provider's API revokes credentials. A nil error means every request was accepted; the caller confirms the outcome with `Verify`, so do not claim success the provider did not report. Without it the registry treats none of the provider's kinds as revocable, whatever their `KindInfo` says | every provider except Azure, sops, Kubernetes, private key, Grafana and PagerDuty |
| `Correlator` (`Observe`, `Identifiers`) | The credential unlocks content that may sit in the scanned repositories: `Observe` runs on every object and returns the identifiers it names (sops recipients, public keys), `Identifiers` says what a credential is known as. `Observe` must be cheap and must not keep a reference to its argument | sops, private key |
| `CommitterCorrelator` (`Committers`) | A match can also come from what the hosting service publishes about the repository's committers, such as an account's SSH keys | private key |
| `ProximityCorrelator` (`Adjacent`) | The credential says nothing about its public half, so it adopts a sighting from its own directory | private key |
| `PathClassifier` (`Classify`) | The kind depends on where the credential lives or what names it, and is settled after attribution | private key |
| `Configurable` (`Configure`) | The provider takes operator configuration from the environment: a privileged credential of the operator's own, an organization's admin key, on which `Kinds` may depend (`patty kinds` marks such kinds with the variables `Configure` reads), or the instances to verify against (`GRAFANA_URL`, `GITLAB_URL`, which the command adds `--grafana-url` and `--gitlab-url` to) | Anthropic, OpenAI, Grafana, GitLab |
| `ServerVerifier` (`AllowPrivateServers`) | `Verify` contacts a server named in the scanned content rather than a fixed public API. Run every such server through `detect.ServerPolicy`, which refuses servers that are not `https` and any private, loopback or link-local address unless told otherwise: a repository must not be able to point patty at the operator's network. A server the operator named on the command line is not subject to it | Kubernetes, Grafana, GitLab, npm |
| `InstanceObserver` (`Instances`, `Bind`) | The credential is accepted by one instance it does not name, a Grafana or a self-managed GitLab. `Instances` runs on every object and returns the origins it names; the scan collects them per repository and `Bind` records them on each of the provider's tokens before `Verify`, the ones from the token's own object first, in whatever field `Verify` reads them back from (`Token.Secret`, as companion material). Pair it with `ServerVerifier`: discovered instances go through the policy, and `detect.AcrossInstances` turns the per-instance answers into one verdict | Grafana, GitLab |
| `DryRunRevoker` (`DryRunRevoke`) | The revocation endpoint can rehearse, or the provider can list and match without touching anything, so the confirmation prompt shows what a revocation would do | Slack, Google Cloud, Anthropic, OpenAI, container registry, npm, GitLab |

### Registering

Add the provider to `peers` in [internal/detect/providers/providers.go](internal/detect/providers/providers.go), in the order it should appear in reports. The container registry provider (`oci`) stays last: it is handed the others so that a registry password which is one of their credentials is reported as theirs. `patty revoke` and the scan pick the new provider up from there; nothing else is wired by hand.

### Docs the pull request updates

- `make docs`, which regenerates the kinds table in [docs/how-it-works.md](docs/how-it-works.md) from `Kinds()`. CI fails on a stale table.
- [docs/how-it-works.md](docs/how-it-works.md): a `###` subsection under *Detection* that says what the shape is, what is verified offline, what the report attributes and what is kept apart; the substring list under *What the scan costs*; and the gitleaks comparison row when gitleaks has no rule for the format.
- [docs/report.md](docs/report.md): a `###` subsection under *What the first line says* (attribution and every `--verify` outcome), one under *Revoking* (the API call, its side effects and the rehearsal, or the owner's manual procedure), a row in *Where credentials live locally*, an entry in *Auditing use* when there is an `AuditNote`, and a `###` under *What leaves your machine* naming every request `--verify` and `--revoke` make.
- [README.md](README.md): a paragraph under *Setup* only when the provider takes operator configuration. The README names no providers anywhere else.
- This file, when the provider introduces a new optional interface.

## Releases

Every squash merge to `main` is a release. The auto-release workflow runs git-cliff on each push and tags the next version, and nothing skips non-feature commits: a `refactor:`, `chore:` or `docs:` merge is a patch release just as a `fix:` is, and a `feat:` bumps the minor version. Batch small changes rather than cutting a string of near-identical releases.

The tag appears within a minute of the merge; goreleaser uploads the 26 assets four to six minutes later, and until then the release lists none, which is not a failed run. Each platform has a raw binary (`patty_linux_amd64`) and an archive (`patty_Linux_x86_64.tar.gz`), `patty_checksums.txt` has the SHA-256 of every file, and every file has a keyless cosign `.bundle`.

To prove a release works:

1. Wait for the asset, not the workflow. `curl -sIL -o /dev/null -w '%{http_code}' https://github.com/teemow/patty/releases/download/<tag>/patty_linux_amd64` answers 404 until the upload and 200 after; poll it in a bounded loop and read the workflow's outcome once at the end with `gh run view --json status,conclusion`. `gh run watch` (and to a lesser degree `gh pr checks --watch`) polls the Actions jobs endpoint every few seconds and trips GitHub's secondary rate limit, which then refuses every `gh` call for a while, however many core requests `gh api rate_limit` still shows.
2. Download the binary and its bundle by direct URL and verify them with the identity `patty self-update` checks:

   ```bash
   cosign verify-blob --bundle patty_linux_amd64.bundle \
     --certificate-identity https://github.com/teemow/github-workflows/.github/workflows/release-go.yml@refs/heads/main \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     patty_linux_amd64
   ```

   Without cosign, check it against `patty_checksums.txt` from the same release: `grep ' patty_linux_amd64$' patty_checksums.txt | sha256sum -c -`.
3. `chmod +x`, run `version`, then scan a scratch repository. Create it with `GIT_CONFIG_GLOBAL=/dev/null` and explicit `GIT_AUTHOR_*`/`GIT_COMMITTER_*` variables, so that a global git configuration (commit signing, hooks) cannot get in the way of a throwaway commit.

## When a scan hangs

The report is written after the last repository, so a run that stops making progress loses everything it found unless it finishes. Do not send `SIGQUIT` for a goroutine dump: it ends the process and its results with it. Attaching a debugger is often not possible either (Yama's `ptrace_scope` refuses an attach without root, and a `go install`ed binary carries no DWARF), so reproduce instead:

- The per-repository status lines on stderr are the only partial record; keep the terminal's scrollback.
- Without `--keep` a mirror is removed when its repository finishes, so the mirrors still under the cache (`~/.cache/patty/<host>/<owner>/*.git` on Linux) are exactly the repositories in flight.
- `git cat-file` children blocked writing to their pipe while patty's threads sit at 100% CPU means a detector is spinning on one object.
- A throwaway `probe/main.go` inside the module that imports `internal/detect/providers` and times `Registry.Find`, `Observe` and `Instances` per blob of the cached mirror, largest blobs first, with a deadline per call and `runtime/pprof` running, names the function within minutes. That is how a loop in the Azure provider's query parsing and a quadratic search on lockfiles were found ([#31](https://github.com/teemow/patty/pull/31)). Delete the probe before committing.
