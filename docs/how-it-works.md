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

### Scanning files

Not every credential on a machine was ever committed: the `.env` in a project folder, the `credentials` file copied into a download directory, the key someone saved next to a checkout. A target that is a directory but not a repository, or a single file, is therefore scanned file by file as it is on disk, and `--files` does the same for the working tree of a local repository, in addition to its object database.

The walk takes every regular file below the directory, reads it through the same parallel readers a repository scan uses, and hands it to the same detector, so everything above about detection, attribution and what a credential unlocks applies to files too: an age identity on disk is matched against the `.sops.yaml` and encrypted files next to it. What the walk leaves out:

- **Symbolic links** are not followed, neither to files nor to directories, so a link into `/` or a home directory cannot drag the whole disk into a scan.
- **`.git` directories** are skipped; a repository's history is read through git, or not at all.
- **Devices, sockets and pipes** are not files.
- **Files larger than `--max-object`** are skipped and counted, like large objects.

`.gitignore` is deliberately *not* honoured: ignored files are exactly where credentials hide. A finding in a file has a path relative to the target and no commit; the report says *on disk* for it, or *in the working tree* when the target is a repository, and a credential found both in history and on disk is one finding with every location.

## Detection

Detection, verification and revocation are organised per **provider**: each provider knows its own credential formats, its API and where its tools keep credentials on a developer machine. The table lists every kind patty ships with. It is generated from the providers themselves (`make docs`), and CI fails when it is out of date.

<!-- BEGIN GENERATED: patty kinds -->

| Provider | Kind | Description | Revocable via API |
|----------|------|-------------|-------------------|
| GitHub | `github-pat` | personal access token (classic) | yes |
| GitHub | `github-fine-grained-pat` | fine-grained personal access token | yes |
| GitHub | `github-oauth` | OAuth access token | yes |
| GitHub | `github-user-to-server` | GitHub App user-to-server token | yes |
| GitHub | `github-refresh` | GitHub App refresh token | yes |
| GitHub | `github-server-to-server` | GitHub App installation token | no |
| Slack | `slack-bot-token` | bot token | yes |
| Slack | `slack-user-token` | user token | yes |
| Slack | `slack-app-token` | app-level token | no |
| Slack | `slack-refresh-token` | refresh token | yes |
| Slack | `slack-config-token` | configuration token | no |
| Slack | `slack-webhook` | incoming webhook | no |
| AWS | `aws-access-key` | access key | yes |
| AWS | `aws-temporary-access-key` | temporary access key (STS) | no |
| Google Cloud | `gcp-service-account-key` | service account key (JSON) | no |
| Google Cloud | `gcp-oauth-user-credentials` | application default credentials of a user (authorized_user JSON) | yes |
| Google Cloud | `gcp-oauth-access-token` | OAuth access token | yes |
| Google Cloud | `gcp-oauth-refresh-token` | OAuth refresh token | yes |
| Google Cloud | `gcp-api-key` | API key | no |
| Azure | `azure-client-secret` | Entra ID application (service principal) client secret | no |
| Azure | `azure-storage-account-key` | storage account access key | no |
| Azure | `azure-sas-token` | shared access signature | no |
| sops | `age-identity` | age identity | no |
| sops | `pgp-private-key` | PGP private key | no |
| Anthropic | `anthropic-api-key` | API key (the fixed AA suffix is padding, not a checksum, but it removes random look-alikes) | with ANTHROPIC_ADMIN_KEY |
| Anthropic | `anthropic-admin-api-key` | Admin API key (same AA suffix) | no |
| Anthropic | `anthropic-oauth-token` | OAuth access token (Claude Code sign-in) | no |
| Anthropic | `anthropic-oauth-refresh-token` | OAuth refresh token (Claude Code sign-in) | no |
| OpenAI | `openai-project-key` | project key (the T3BlbkFJ marker is not a checksum, but it removes random look-alikes) | with OPENAI_ADMIN_KEY |
| OpenAI | `openai-service-account-key` | service account key (the T3BlbkFJ marker is not a checksum, but it removes random look-alikes) | with OPENAI_ADMIN_KEY |
| OpenAI | `openai-admin-key` | admin key (the T3BlbkFJ marker is not a checksum, but it removes random look-alikes) | with OPENAI_ADMIN_KEY |
| OpenAI | `openai-legacy-key` | legacy user key (the T3BlbkFJ marker is not a checksum, but it removes random look-alikes) | no |
| Kubernetes | `kubernetes-client-certificate` | client certificate | no |
| Kubernetes | `kubernetes-service-account-token` | service account token | no |
| Kubernetes | `kubernetes-token` | bearer token | no |
| Kubernetes | `kubernetes-basic-auth` | basic auth login | no |
| Kubernetes | `kubernetes-secret-manifest` | Secret manifest with plaintext values | no |
| private key | `ssh-private-key` | SSH private key | no |
| private key | `tls-private-key` | TLS or generic PEM private key | no |
| private key | `cosign-private-key` | cosign signing key (encrypted) | no |
| Registry | `docker-hub-pat` | Docker Hub personal access token | yes |
| Registry | `docker-hub-oat` | Docker Hub organization access token | no |
| Registry | `quay-robot-token` | Quay robot account token | no |
| Registry | `quay-oauth-token` | Quay OAuth access token | no |
| Registry | `docker-hub-login` | Docker Hub login | no |
| Registry | `quay-login` | Quay login | no |
| Registry | `acr-login` | Azure Container Registry login | no |
| Registry | `ghcr-login` | GitHub Container Registry login | no |
| Registry | `gcr-login` | Google Artifact Registry login | no |
| Registry | `ecr-login` | Amazon ECR login | no |
| Registry | `harbor-login` | Harbor login | no |
| Registry | `registry-login` | registry login | no |

<!-- END GENERATED: patty kinds -->

*Revocable via API* is what `--revoke` can do from patty. Every other kind comes with its owner's procedure in the report, see [revoking](report.md#revoking). A kind marked with an environment variable becomes revocable once that variable is set, see the README's Setup.

The sections below say how each provider finds its credentials without contacting anyone, and what the shape alone reveals.

### GitHub

The classic families share one layout: a prefix that names the family, followed by 36 characters whose last six are a [CRC32 checksum](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) of the first 30, Base62-encoded. `ghp_` is a personal access token, `gho_` an OAuth token, and `ghu_`, `ghs_` and `ghr_` are a GitHub App's user-to-server, installation and refresh tokens. patty recomputes the checksum: a string with the right prefix and length but a wrong checksum is not a token and is not reported. That removes the false positives a pure regex match has to live with -- a `ghp_` followed by 36 random alphanumerics in a test fixture, a hash, a minified bundle -- and is why the report needs no allow-list to stay readable.

The fine-grained format (`github_pat_`, 22 characters, `_`, 59 characters) has no documented checksum. It is matched on its shape alone and best confirmed with `--verify`.

### Slack

Slack tokens have no checksum, but their shapes are strict: fixed-length numeric ids separated by dashes and a secret of a fixed length and alphabet. A bot token starts with `xoxb-`, a user token with `xoxp-`, an app-level token with `xapp-1-`, a refresh token with `xoxe-1-`, and a configuration or rotating access token with `xoxe.xoxb-1-` or `xoxe.xoxp-1-`. An incoming webhook URL has a fixed host, route (`https://hooks.slack.com/services/`, `/workflows/` or `/triggers/`) and id layout.

The numeric ids are the workspace (team) and the user, bot or app the token was issued to. So the report attributes a bot token, user token, app-level token or webhook without contacting Slack; refresh and configuration tokens carry no ids and are matched on shape only.

### AWS

An access key id is a four-character prefix and sixteen characters of the base32 alphabet (`A-Z`, `2-7`), so it never contains `0`, `1`, `8` or `9`. `AKIA` (also `ABIA`, `ACCA` and `A3T…`) is a long-lived access key, `ASIA` a temporary key from STS. The base32 body encodes the id of the account the key was issued in, which patty decodes offline and shows as *account 123456789012*.

A key id is only usable together with its secret access key, forty characters of base64, so patty looks for one in the same object: first a run named by `aws_secret_access_key`, `SecretAccessKey` or `secret_key`, then one on the key's own line or the line after it, then the closest one. For a temporary key it also looks for the session token that goes with it. The report says whether it found a *key pair* or a *key id only*. The secret is what makes a leak exploitable, but it is never shown, fingerprinted or written to the JSON; the key id is the credential's name throughout.

### Google Cloud

A service account key is a JSON document, and its own fields say what it is: `"type": "service_account"`, the account's `client_email`, the `private_key_id`, the `project_id`, and the RSA `private_key` as PEM. patty looks for the `type` marker as a JSON string value and reads the object around it, wherever the document sits: a `key.json` of its own, a block scalar in a Helm values file or a ConfigMap, a Terraform heredoc, one line in an `.env` file, escaped inside another JSON string (the `_json_key` password of a Docker config), or base64 in a Kubernetes Secret, which the [Secret rescan](#kubernetes) hands over decoded.

The finding is named `client_email/private_key_id`, which reveals nothing and is what `gcloud iam service-accounts keys list` shows, and attributed *service account …, project …*. The private key travels apart and is never shown, fingerprinted or written to the JSON. A document without its private key or account is a stub, not a finding; a Terraform `google_service_account` resource or a YAML mapping with `type: service_account` is not a document.

The `authorized_user` document `gcloud auth application-default login` writes is read the same way and named by its refresh token, with the OAuth client id and secret kept apart. Google only accepts a refresh token from the client it was issued to, so the client is what makes the finding verifiable.

The bare token shapes have no owner in them and are matched on shape alone. An access token is `ya29.` and an undocumented body of 60 to 250 characters of the URL-safe base64 alphabet, with a dot for the `ya29.c.` family. A refresh token is `1//0` and 40 to 120 characters; an API key is `AIza` and exactly 35. A refresh token found bare is reported as *found without its OAuth client*; the same token inside an `authorized_user` document is that document's finding, not a second one.

### Azure

A client secret is the one Azure credential with a shape: 40 characters for current secrets, with `Q~` at the fifth position, after three characters of `[A-Za-z0-9_~.]` and a digit, and 31 to 34 characters of `[A-Za-z0-9_~.-]` after it. That is enough to find one, not enough to use one: Entra ID only accepts a secret at its tenant's token endpoint, together with the application's client id. patty looks for both in the same object, as GUIDs behind the words that name them: `tenant`, `tenantId`, `AZURE_TENANT_ID`, `ARM_TENANT_ID` or the tenant in a `login.microsoftonline.com/…` authority URL; `client_id`, `clientId`, `appId`, `applicationId` and their variants. That covers `.env` files, Terraform providers, Helm values, the JSON `az ad sp create-for-rbac` prints (`appId`, `password`, `tenant`) and its `--sdk-auth` form (`clientId`, `clientSecret`, `tenantId`). Ids written before the secret are preferred over ids after it, so several principals in one file each get their own. The report says *app … in tenant …*, or which id was not found nearby; the ids travel apart from the secret.

A storage account key is 64 random bytes in base64, 86 characters and `==`, and on its own indistinguishable from any other 512-bit key (a Cosmos DB key, for one). So it is only a finding next to the name of its account: the `AccountName=` of the connection string it stands in, the first label of a `<name>.blob.core.windows.net` endpoint (or `dfs`, `file`, `queue`, `table`, `web`), or the name behind `AZURE_STORAGE_ACCOUNT`, `storage_account_name`, `accountName` and the like, always 3 to 24 lower-case letters and digits as Azure requires. An unpaired run is noise and is not reported.

A shared access signature is a query string with `sv`, `se` and `sig`, with or without its URL. patty takes the whole URL when there is one, names the finding by the `sig` value and attributes it with the resource, the `sp` permissions and the `se` expiry, saying *expired* when that has passed. A bare token (a CI variable holding just the query) is reported with *resource unknown*. ACR passwords and tokens are the [registry provider's](#container-registries) business and are not reported here again.

### sops

An age identity is `AGE-SECRET-KEY-1` followed by 58 characters of the Bech32 alphabet, the last six of which are a checksum. patty parses every candidate with the age library; a string that fails the checksum is not an identity and is not reported, just like a classic GitHub token with a wrong CRC. The public key (`age1…`) is derived from the secret and shown as the attribution: it is not secret, and it is what a `.sops.yaml` lists as a recipient.

A PGP private key is found by its armor header and parsed as an OpenPGP key ring; it is a finding only when the key parses and its self-signatures verify. It is named by the fingerprint of its primary key, the forty hex characters `gpg --list-secret-keys` and sops show. The armored block itself is not kept. The report says whose key it is (fingerprint and user id) and whether the secret material is passphrase-protected, which makes the leak smaller as long as the passphrase was not committed next to it. Encrypted sops content (`ENC[…]` values, `sops:` metadata) is ciphertext and is not reported.

What makes a leaked identity matter is what it decrypts. While scanning, the sops provider also watches every blob that looks like sops material -- a `.sops.yaml` with `creation_rules`, or a file with `ENC[` values or a `sops:` metadata block -- for `age1…` recipients and forty-character PGP fingerprints, and remembers only which object named which recipient. After the scan every identity found is matched against those sightings, and the report lists the repositories and files encrypted to it. The identity file itself names its public key in a comment but is not sops material, so it does not count as something the key decrypts. Recipients in repositories that were not scanned are, of course, not known.

### Anthropic

No Anthropic key carries a checksum, but none is a bare random string either. An API key (`sk-ant-api03-`) or Admin API key (`sk-ant-admin01-`) is its prefix, 93 characters of the URL-safe base64 alphabet and a fixed `AA`. The suffix is padding, not a checksum, but a random 95-character run ends in `AA` once in four thousand times, which is what separates a key from a hash in a test fixture.

The OAuth access and refresh tokens Claude Code stores after `claude auth login` (`sk-ant-oat01-`, `sk-ant-ort01-`) have no documented format. patty accepts 80 to 120 characters of the same alphabet after the prefix, which is specific enough given the prefix. Neither OAuth family is in gitleaks' rules. What a key belongs to is not in its shape; `--verify` answers that.

### OpenAI

Every OpenAI key embeds `T3BlbkFJ`, which is `OpenAI` in base64, at a fixed position. Project (`sk-proj-`), service account (`sk-svcacct-`) and admin (`sk-admin-`) keys have it between two runs of 74 or 58 characters; legacy user keys (a bare `sk-`) have it between two runs of 20 alphanumerics. patty searches for the marker and checks the shape around it; a marker in any other position, or with a run of any other length, is not a key. What a key belongs to is not in its shape; `--verify` answers that.

### Kubernetes

A kubeconfig is a YAML document with `kind: Config`, a list of clusters, a list of users and the contexts that pair them. patty reads every user. A client certificate embedded as `client-certificate-data` with its `client-key-data` is decoded and parsed (`crypto/x509`), and is only a credential when the key belongs to the certificate. The finding is named by the certificate's SHA-256 fingerprint and attributed with its subject (`CN=`), the groups in its organization field (`system:masters` is the one that grants everything), its issuer, its expiry and the server of the cluster the user's context points at; an expired certificate says so. A `token` is a bearer token: a JWT whose claims name a Kubernetes service account is reported as a service account token, a JWT of some other issuer (an OIDC id token pasted in) names that issuer in the attribution, and anything else is an opaque bearer token. `username` and `password` are a basic auth login, named `host/username` with the password kept apart. Users that only name files or plugins (`client-certificate`, `client-key`, `tokenFile`, `exec`, `auth-provider`) carry no secret and yield nothing.

Service account tokens are JWTs, and a JWT stands out: three base64url parts separated by dots, the first two of which decode to JSON objects, the first starting with `eyJ`. patty decodes every word-bounded candidate, without verifying the signature (it has no key to do so and never claims to), and looks at the claims. A legacy token is issued by `kubernetes/serviceaccount` and names its account in flat `kubernetes.io/serviceaccount/…` claims; a bound token carries a `kubernetes.io` object with the namespace, the account, the pod it was projected into, and an expiry. Either is reported with *serviceaccount namespace/name*, the pod, and *expires* or *no expiry (legacy token)*. A JWT whose claims say nothing about Kubernetes is not a finding: an OIDC id token or a session token belongs to whoever issued it, and a future provider may claim it. The decoder is shared, so it can.

Secret manifests are the multiplier. A YAML or JSON document with `kind: Secret` -- on its own, in a multi-document stream separated by `---`, or as an item of a `List` -- has every `data` value base64-decoded and every `stringData` value taken as it is, and the decoded bytes are searched with the whole registry. A GitHub token, an AWS key pair, a Docker config or a kubeconfig inside a Secret is found by its own provider and placed at the line of the Secret's key, attributed *in Secret namespace/name, key KEY*. Left alone are values that are sops ciphertext (`ENC[…]`), documents that carry a `sops:` metadata block, templated values (`{{ }}`, `${ }`, `.Values`), empty values and values that are not base64. A value is decoded once (a manifest inside a manifest is not opened again) and at most 1 MiB of it is searched. A document that does not parse, a Helm template with bare `{{ }}` blocks, is skipped rather than guessed at. Independently of what the values turn out to be, a Secret with at least one value in the clear is reported as `kubernetes-secret-manifest`, named *namespace/name*, with the list of its keys: plaintext secret material in git is a leak whatever its shape, and a random password has no shape to match. The values themselves are never shown or fingerprinted.

### Private keys

Private keys are found by their armor header. Every block whose label names a private key is cut out up to its matching end marker: OpenSSH, PKCS#8 (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`), SEC1 (`EC PRIVATE KEY`), DSA, and the `ENCRYPTED SIGSTORE PRIVATE KEY` or `ENCRYPTED COSIGN PRIVATE KEY` block cosign writes. The block is normalized first: `\n` escapes, as a JSON, Terraform or `.env` string carries a key, become newlines, and indentation (a YAML block scalar) and carriage returns go, so the same key is one finding however it was pasted. Then it is parsed (`golang.org/x/crypto/ssh`, `crypto/x509`); a block that does not parse, a placeholder or a truncated key, is not reported.

A key is named by the fingerprint of its public half, which reveals nothing and is what `ssh-keygen -lf`, GitHub's settings page and `openssl pkey -pubout` show: the OpenSSH form (`SHA256:…`) for a key in OpenSSH format, the hex SHA-256 of the SubjectPublicKeyInfo for a PEM key. A passphrase-protected OpenSSH key still has its public key in the clear part of the container and is named by it. An encrypted PKCS#8 or legacy PEM block, and a cosign key (an scrypt/secretbox document whose public half is not derivable), are named by the hash of the block.

The attribution says the algorithm and size (*ed25519*, *RSA 4096*, *ECDSA P-256*), whether the key is *encrypted* or *unencrypted*, and the comment an OpenSSH key carries (`ssh-keygen -C`, usually *user@host*), which the ssh library does not expose and patty reads from the end of the private section. Unencrypted keys are listed before encrypted ones. A PEM key starts out as `tls-private-key`, ssh-keygen having written OpenSSH format since 2018, and becomes `ssh-private-key` once the scan knows where it lives (`id_*`, a `.ssh/` directory) or that an SSH public key or GitHub account names it (see below). DSA keys are SSH keys wherever they are, since DSA is only used for SSH. The key material travels apart from the finding, only for the one verification described in [the report](report.md#verifying-ssh-keys-against-github), and is never shown, fingerprinted or written to the JSON.

Left to others: the `private_key` of a Google Cloud service account document, which is [that provider's](#google-cloud) finding with its account and key id; PGP private key blocks, which are the [sops provider's](#sops); and certificates and public keys, which are not credentials.

What makes a leaked key matter is what its public half is trusted by, so the private key provider also watches every scanned object, the decoded values of Secret manifests included, for public halves:

- SSH public keys on a line of their own (`authorized_keys`, `.pub` files) or inside a string (a Terraform `github_repository_deploy_key`, an Ansible `authorized_key`, cloud-init `ssh_authorized_keys`), decoded and checked against their algorithm name.
- `CERTIFICATE` blocks, parsed for their names, expiry and issuer.
- `PUBLIC KEY` blocks: the `cosign.pub` of a signing key, and the keys pinned in a Kyverno `verifyImages` rule or a policy-controller `ClusterImagePolicy`.

Each is remembered under the fingerprint forms a key is named by, and the report lists, per key, the files that name it: *authorized_keys*, *tls/server.crt: certificate for www.example.com, expires 2030-06-01, issuer Example CA*, *policies/verify.yaml: public key (ECDSA P-256), pinned by Kyverno ClusterPolicy verify-images*. A cosign key, which says nothing about its public half, adopts the `PUBLIC KEY` file in its own directory, the `cosign.pub` written next to `cosign.key`, and through it every policy that pins that key.

For SSH keys there is one more source. GitHub publishes the SSH public keys of every account at `github.com/<login>.keys`. For every repository that holds an SSH key, patty takes the logins it can read from the commits (the `12345+login@users.noreply.github.com` addresses of authors and committers) and, with a token, the repository's contributors, and fetches those files, at most fifty per repository and once per login and run, to say *matches octocat's GitHub SSH key*. That is public information about a public key, not a leak; nothing about the private key is sent.

### Container registries

Registry logins are not tokens with a prefix but a username and a password for one host, kept in the `auths` map of a Docker config. That config turns up as `~/.docker/config.json`, as the `.dockerconfigjson` of a Kubernetes Secret of type `kubernetes.io/dockerconfigjson` (base64 under `data`, or in the clear under `stringData`), and inline in Helm values as an escaped JSON string or as base64. Each entry keeps its login either as `username` and `password` or as `auth`, the base64 of `user:password`. patty finds the `auths` key, parses the map that follows it, and peels at most two base64 layers (the Secret's and the entry's) to get at each login. Entries that only name a `credsStore` or `credHelpers` keep their secret in the OS keychain and yield nothing.

Each login is one finding named `host/username`, which reveals nothing and is shown in full, with the kind derived from the host: Docker Hub, quay.io, `*.azurecr.io`, ghcr.io, gcr.io and `*.pkg.dev`, ECR (`*.dkr.ecr.*.amazonaws.com`, whose passwords expire within twelve hours), a host with *harbor* in its name, and everything else as `registry-login`. The password travels apart from the name and is never shown, fingerprinted or written to the JSON. When the password is itself a Docker Hub or Quay token, the finding is that token, so the same credential is one finding whether it turns up in a pull secret or in a CI variable. When it is another provider's credential, a GitHub token used against ghcr.io, the login says *password is a GitHub personal access token, reported separately* and that provider's finding carries the token; patty hands it over itself when the password sat in base64 no other provider could see. A `Basic` Authorization header is decoded the same way when the text around it names a registry, a `/v2/` URL or a known registry domain; a Basic header aimed at anything else is left alone.

Docker Hub tokens have a prefix (`dckr_pat_` for personal, `dckr_oat_` for organization access tokens) but no documented length, so patty accepts 24 to 40 characters of the URL-safe base64 alphabet after it and looks for the username written next to the token (`username`, `user`, `-u`), which a Docker Hub token is useless without. Quay robot tokens are 64 upper-case alphanumerics with no prefix at all, indistinguishable from a hash on their own, so one is only reported next to its robot's `org+robot` name, and a run that is all hexadecimal is a hash. Quay OAuth tokens, 40 alphanumerics of mixed case, are only reported near a `quay.io` mention and never from inside a base64 value the decoder already consumed. Azure and Harbor passwords have no shape of their own and are found through the config decoder only. None of these shapes has a rule in gitleaks.

### What the scan costs

The scan itself is a handful of substring searches per object: `gh`, `github_pat_`, `xoxb-`, `xoxp-`, `xapp-1-`, `xoxe`, `https://hooks.slack.com/`, `AKIA`, `ASIA`, `ABIA`, `ACCA`, `A3T`, `service_account`, `authorized_user`, `ya29.`, `1//0`, `AIza`, `Q~`, `==`, `sig=`, `sk-ant-`, `T3BlbkFJ`, `AGE-SECRET-KEY-1`, the PGP armor header, the three sops markers, `auths`, `dockerconfigjson`, `Basic `, `dckr_pat_`, `dckr_oat_`, `eyJ`, `kind: Config` and `kind: Secret`, the PEM armor header and the SSH algorithm names `ssh-`, `ecdsa-sha2-` and `sk-`, plus one pass over the alphanumeric runs for Quay tokens. Each candidate gets an exact shape check and, where the format has one, a checksum check.

Everything more expensive happens only where a candidate asks for it: only an object that holds an AWS key id is searched for its secret, only the JSON object around a Google `type` marker is parsed, only an object that holds an Azure secret or key is searched for its tenant, client or account, only sops material for recipients, only a Docker config is parsed as JSON, only a kubeconfig, a Secret manifest or an image policy as YAML, and only an armored block as a key or certificate. The detector runs at about 1 GB/s per core; `git` decompressing objects is the bottleneck, which is why the readers run in parallel.

## Compared with gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks) is a general secret scanner with more than 200 rules, allow-lists, baselines and CI integrations. patty is a narrow tool with one question: *is a credential of one of the [kinds above](#detection) anywhere in this repository's past?* Where they overlap the differences are:

| | gitleaks `git` | patty |
|---|---|---|
| History covered | commits reachable from refs (`git log -p --all`) | every object in the database, plus `refs/pull/*` and force-pushed or deleted commits fetched from GitHub |
| Unit of work | each commit's diff; content that appears in many commits is scanned as often | each object once |
| The credentials in the [detection table](#detection) | regex + entropy (no rule for Anthropic OAuth tokens, Docker configs, Docker Hub or Quay tokens, Azure storage keys or SAS tokens; a Secret manifest, a JWT and a service account key are matched by shape, not opened) | exact shape + checksum where the format has one, offline attribution, optional live check; for sops identities, the files they decrypt; Secret manifests are decoded and their values searched, JWTs classified by their claims |
| Private keys | one regex for any armored private key block | the block is parsed and named by its public key; the report says which certificate, `authorized_keys`, `cosign.pub`, image policy or GitHub account trusts it, and `--verify` asks GitHub whether an SSH key still opens an account |
| Where it points | commit and file of each occurrence | oldest introducing commit, all refs that still contain it, and how orphaned commits went unreachable |
| Scope | one repository or directory | any number of repositories, whole owners, plain directories and files, with a disk budget |
| Everything else | Stripe, Twilio, ... | only the kinds in the [detection table](#detection) |

Use both: gitleaks in CI on every push, patty when you want to know what is already out there.

## Disk budget

Mirroring an organization can mean tens of gigabytes. patty never fills a drive:

- Before cloning it checks the repository size GitHub reports (times three, which is what a mirror with pull request refs has been measured at) against the remaining **`--max-disk`** budget and the drive's free space minus **`--min-free`**. A repository that does not fit is **skipped** with a message, not cloned halfway.
- Mirrors are removed as soon as their scan finishes, unless **`--keep`** is set. With `--keep`, the least recently used mirrors are evicted when the budget runs out, and a re-run of a kept mirror is a `git fetch` rather than a fresh clone.
- Mirrors are bare: no working tree is ever checked out.
- Objects larger than **`--max-object`** are skipped and counted; a token in a 200 MB binary is not what patty is for.

`patty cache` shows what is kept, `patty cache clean` removes it.
