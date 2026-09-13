# Reading the report

Each distinct credential is listed once, with every place it was found across all scanned repositories (the footer says *targets* when a plain directory or file was among them):

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

Each credential is three things: the first line says what it is, the location lines say where it was found and how reachable that still is, and the `↳` lines say what to do about it. Active credentials come first. Revoke them before anything else.

## What the first line says

The kind names the provider and the family: `github-pat`, `slack-bot-token`, `kubernetes-client-certificate`. The [detection table](how-it-works.md#detection) lists every kind. After the redacted value and the [fingerprint](#fingerprints) comes what the credential's own shape reveals about its owner, and with `--verify`, what its provider says about it. A verification that could not be completed (network, rate limit, an unexpected answer) is *unknown*, never a verdict; a credential nobody can be asked about is *unverifiable*.

### GitHub

A token's shape reveals nothing about its owner. With `--verify`, an active token shows the user and scopes, the application it was issued to when GitHub reports one (GitHub CLI, Copilot, Desktop, VS Code, or the raw OAuth client id), and its expiry date if it has one.

### GitLab

A routable personal access or runner token names its home, *cell 1, organization 2, group 10, user 35*, the ids in its payload; a legacy token says nothing. A deploy token says whether its username (`gitlab+deploy-token-N`) was found next to it. With `--verify`, a live personal access token shows the instance that accepted it, the token's name, user id, scopes and last use, and its expiry date; one every candidate instance rejects is *revoked*, each instance named; one an instance answers 200 for but lists as revoked or inactive is *revoked* too; one without the `api` scope is *accepted, but its scopes do not allow reading …* and live all the same. A live runner token shows the runner it belongs to, a live deploy token the login it was accepted as; a deploy token without its username is *unverifiable*. Job, trigger, feed, incoming mail, agent, application, feature flag and SCIM tokens are *unverifiable*, each with the reason: a job token dies with its job, a trigger token can only be tested by starting a pipeline, and the rest are only accepted by endpoints the token does not name. [Instances a token does not name](#instances-a-token-does-not-name) says which instances are asked.

### Slack

A token names the workspace (team) and the user or bot it was issued to; a webhook URL names the workspace. With `--verify`, an active token shows the workspace, the user or bot, and the scopes.

### AWS

A key id names the account it was issued in, and whether its secret was found next to it (*key pair*) or not (*key id only, secret not found nearby*). With `--verify`, an active key shows the ARN of the user or role session it belongs to. A key id found without its secret cannot be verified and is *unverifiable*: treat it as live.

### Google Cloud

A service account key is named `client_email/private_key_id`, which is what `gcloud iam service-accounts keys list` shows and reveals nothing, and attributed *service account deploy@example-project.iam.gserviceaccount.com, project example-project*; the private key is kept apart. An `authorized_user` document is named by its refresh token and attributed *ADC for OAuth client 123456789012*, the project number the client id starts with; a bare refresh token says *found without its OAuth client*.

With `--verify`, a live service account key shows *service account … in project*. One whose key was deleted is *revoked* with *key deleted: the signature is no longer known*; one whose account was deleted or disabled says so. A live access token shows the account and scopes tokeninfo reports, the OAuth client it was issued to and when it expires. A refresh token that came with its client shows the client and the scopes the exchange granted; one found bare is *unverifiable*, since Google only accepts a refresh token from the client it was issued to. An API key is *unrestricted* when the Discovery API accepts it and *restricted* when the key exists but may not call that API; a deleted key is *revoked*. A service account key whose private key does not parse is *unverifiable* with *malformed key*.

### Azure

A client secret says what was found next to it: *app aaaaaaaa-… in tenant 11111111-…*, or *tenant id not found nearby*, *client id not found nearby*, *tenant and client id not found nearby*. A storage account key names its *storage account*. A shared access signature names *resource host/path, permissions rwdl, expires 2030-01-01*, or *expired 2024-06-30*, or *bare token, resource unknown*.

With `--verify`, a live client secret shows the app and tenant, and the display name of the application when the token names it. It is *revoked* when Entra answers *invalid client secret* (`AADSTS7000215`) or *the client secret has expired* (`AADSTS7000222`). An application the tenant does not know (`AADSTS700016`) or a tenant that does not exist (`AADSTS90002`) is *unknown*, with the hint that the id found nearby may be the wrong one. A secret without both ids is *unverifiable*, with the missing one named.

A live storage key shows *storage account name, N containers*. One the account no longer accepts is *revoked* (*key rotated*), and so is one whose account answers 404 (*does not exist any more*); a firewall or network rule that refuses the request before judging the key is *unknown*. An expired signature is *revoked* without a request. A live one shows *accepted by host/path*, or *accepted, but not permitted to read it* when the signature is valid for something else; one the service rejects with `AuthenticationFailed` is *revoked*. A bare token, or a URL that is not an https Azure Storage endpoint, is *unverifiable* and is not contacted.

### sops

An age identity names its public key (*recipient age1…*), which is what a `.sops.yaml` lists. A PGP private key names its fingerprint and user id and says whether it is *passphrase-protected*. Neither has an issuer to ask, so `--verify` reports both as *unverifiable*: an identity is valid by construction, the checksum or the key packets said so when it was found, and the [*decrypts* line](#what-to-do-about-it) is what tells how much it matters.

### Anthropic

Anthropic says nothing about a key that merely authenticates, so an active key shows *accepted by the API*; an admin key shows the organization it administers. A key that authenticates but may not list models (*accepted, but not allowed to list models*) is live all the same. With `ANTHROPIC_ADMIN_KEY` set (see the README's Setup), a key of that organization is also named the way the Console lists it: *key CI deploy, workspace wrkspc_…, created by user user_…*; a key that is not in the organization's list stays at *accepted by the API*. OAuth refresh tokens (`sk-ant-ort01-`) are *unverifiable*: they are exchanged through the OAuth client, not usable against the API.

### OpenAI

OpenAI too says nothing about a key that merely authenticates, so an active key shows *accepted by the API*, with the organization and project the API names in its response headers. With `OPENAI_ADMIN_KEY` set (see the README's Setup), a key of that organization is named the way the Console lists it: *key deploy in project Beta, owned by service account ci*; a key that is not in the organization's list stays at *accepted by the API*. A 429 is reported as *unknown*: a key whose quota is exhausted answers exactly like a rate-limited one, and is still live.

### Grafana

A Cloud token names its org, token name and region, a legacy API key its name and org id; a service account token says nothing. With `--verify`, a live service account token or API key shows *accepted by grafana.example.com as sa-1-deploy, org 1*, with *Grafana admin* when it is one, or *accepted by …, but not allowed to read /api/user*; one every candidate instance rejects is *revoked*, each instance named; one with no candidate instance at all is *unverifiable* with the hint to pass `--grafana-url`. A live Cloud token shows the org, its own name, the access policy it belongs to and that policy's scopes, and its expiry date when it has one; one whose scopes do not include `accesspolicies:read` is live and says so; one grafana.com rejects is *revoked*.

### PagerDuty

A routing key names the configuration key it was found under (*under integration_key*) or its Alertmanager receiver (*routing_key of receiver pagerduty-critical in Alertmanager config*); an API key says nothing. With `--verify`, a live user key shows *user Jane Doe jane@example.com, role admin*, a live general access key *general access key (account-level)*; one PagerDuty rejects is *revoked*. A routing key is always *unverifiable*, *verifying would page the on-call; treat as live*, and is never sent anywhere.

### npm

A token found on an `.npmrc` line names the registry the line is for, *in an .npmrc for the default registry* or *for npm.example.com*; a bare token says nothing. With `--verify`, a live token shows *user alice on registry.npmjs.org* and, when the registry lists it, whether it is a *publish*, *automation* or *read-only* token, when it was created and the CIDR it is bound to; a granular token the registry does not list is live all the same. One the registry rejects is *revoked*. A token for a private registry is checked against that registry, subject to the same restrictions as [API servers](#verifying-against-api-servers).

### Kubernetes

A client certificate is named by its SHA-256 fingerprint and attributed with what the certificate says about itself: *CN=kubernetes-admin groups=system:masters issuer kubernetes, expires 2027-10-18, server https://k8s.example.com:6443*, the server being the cluster the kubeconfig's context points the user at. A certificate past its expiry says *expired* instead, and `--verify` reports it as *revoked* without contacting anything: no API server accepts an expired certificate. A service account token names its *serviceaccount namespace/name*, the pod a bound token was projected into, and *expires* or *no expiry (legacy token)*; a bound token past its expiry is *revoked* the same way. Any other bearer token of a kubeconfig user is a *bearer token*, or *JWT issued by …* when it is one. A basic auth login is named *host/username* with the password kept apart.

A service account token found outside a kubeconfig, in an environment file or a manifest, has no server to be checked against and is *unverifiable*. With `--verify` and a server, a live credential shows *accepted by host, Kubernetes v1.31.2*, for a certificate *as CN=…*. One the server rejects with 401 is *revoked*, and so is a certificate the server refuses in the TLS handshake or answers as `system:anonymous`. A server that cannot be reached, does not resolve, or is not trusted (a self-signed cluster whose kubeconfig embeds no CA) is *unknown*, never a verdict. [Verifying against API servers](#verifying-against-api-servers) says which servers are contacted at all.

A credential found inside a Secret manifest carries the Secret as its attribution, *in Secret build/ci-credentials, key GITHUB_TOKEN*, followed by whatever the credential's own shape says in parentheses; its location is the line of that key. The same token in a Secret and in an `.env` file is one credential with two locations. The Secret itself is reported as `kubernetes-secret-manifest`, named *namespace/name* (or the bare name when the manifest sets none) and shown in full, with the *type* when it is not Opaque and the list of its *keys*, never the values. It is *unverifiable*, since nothing can check a random password, and is listed after the credentials patty can put a name to. `--ignore kubernetes-secret-manifest` leaves the kind out entirely; `--ignore` takes kinds as well as fingerprints. How the values are decoded and searched is described in [how patty works](how-it-works.md#kubernetes).

### Private keys

A private key is named by the fingerprint of its public half, shown in full because it reveals nothing: the OpenSSH form (`SHA256:…`, what `ssh-keygen -lf` and GitHub's settings page show) for a key in OpenSSH format, the hex SHA-256 of the SubjectPublicKeyInfo for a PEM key, and `sha256:` with the hash of the block for encrypted material whose public half cannot be read (an encrypted PKCS#8 or legacy PEM key, a cosign key). The attribution says what the key is and whether it is usable as it stands: *ed25519, unencrypted, comment deploy@ci*, *RSA 4096, encrypted*, *ECDSA P-256, unencrypted*, and for a cosign key *encrypted with scrypt/nacl/secretbox, public key not derivable*. When one of the repository's committers publishes the same public key on GitHub, the attribution goes on: *matches octocat's GitHub SSH key*. Unencrypted keys are listed before encrypted ones; a passphrase-protected key is worth only what its passphrase is, as long as that was not committed next to it.

With `--verify`, an unencrypted SSH key is offered to github.com once, as user `git`, with no command and no shell (see [verifying SSH keys against GitHub](#verifying-ssh-keys-against-github)). *Accepted by github.com as octocat: the key is listed on that account* is *ACTIVE*, and so is *accepted by github.com: a deploy key, or the key of an account that did not commit here*; *github.com rejects it: on no account and no deploy key* is *revoked*. A server that cannot be reached, or that presents a host key other than GitHub's published ones, is *unknown*, never a verdict. An encrypted SSH key, a TLS key and a cosign key are *unverifiable*: there is no one to ask, and the *matches* line is their evidence.

### Container registries

A registry login is named `host/username` (`quay.io/acme+ci`, `example.azurecr.io/deploy`), which reveals nothing and is shown in full; the password is kept apart and is never shown or written to the JSON. The attribution repeats host and user, says *temporary: expires within 12 hours* for an ECR login, and *password is a GitHub personal access token, reported separately* when the password is another provider's credential, which then has its own entry. A Docker Hub token names the *user* found next to it or says *username not found nearby*; a Quay robot token names its *robot*.

With `--verify`, a live login shows the host and user the registry accepted, *accepted but forbidden to request a token* when the registry answers the login 403 but a request without credentials 401, so it knows the login, and for Docker Hub the account the login response names. A registry that answers 403 to the login and to no credentials alike, as ghcr.io does for a wrong password, rejected the login: *revoked*, with that reason. A login whose registry is filled in when the workflow runs (`${{ env.REGISTRY }}`) is *unverifiable*. A Docker Hub token without a username is *unverifiable*: Docker Hub tokens only work together with their username. A registry that answers `/v2/` without credentials cannot confirm a login and is reported as *unknown*.

## Where it was found

Under the first line, one line per location names the repository, path, introducing commit, date, author and commit subject. The second line of each location says how reachable the commit still is:

- **on main, v1.2, PR #7** -- ordinary history; the token is in the repository as anyone clones it. `--all-refs` lists all of them instead of `+405 more`.
- **only reachable through pull request refs** -- someone rewrote the branch to remove it, but the pull request that carried it still serves the old commits (`refs/pull/N/head`), and so does every fork that was made in between.
- **orphaned** -- no ref reaches the commit anymore; GitHub still serves it by SHA to anyone who has it (the activity feed, an old notification email, a CI log). When patty knows how it went unreachable, it says so: *force-pushed away from main on 2026-01-06 by jane*.
- **on disk** / **in the working tree** -- the token sits in a file of a directory that is no repository, or in the working tree of one scanned with `--files`; there is no commit to name and nothing to rewrite, delete the file or the line after revoking. A token found both in history and on disk is one credential with both locations.

## What to do about it

The `↳` lines under a credential its provider has not rejected yet say what to do about it:

- **decrypts** -- for an age identity or PGP key: the repositories and files among the scanned ones that list its public key or fingerprint as a sops recipient, `acme/infra: 42 files (clusters/prod/secrets.sops.yaml, +41 more) · acme/app: 3 files (…)`. That is what the leak is worth: everything in those files, in every commit that holds them, is readable to whoever has the key. When nothing matches the line says so; the key may still decrypt files in repositories that were not scanned.
- **matches** -- for a private key: the files among the scanned ones that name its public half, and what they say about it. For an SSH key that is the `authorized_keys`, `.pub` file or Terraform resource that lists the public key, with the key's comment, `acme/infra: 2 files (authorized_keys: ssh public key, comment deploy@ci, infra.tf: ssh public key)`; every host whose `authorized_keys` lists it, and every GitHub account or deploy key that carries it, is open to whoever has the private key. For a TLS key it is the certificate the key belongs to, with the names it covers, its expiry and its issuer, `tls/server.crt: certificate for www.example.com, expires 2030-06-01, issuer Example CA`, or *expired 2020-01-01* when it has run out; a certificate in the `tls.crt` of a Kubernetes Secret counts like one in a file. For a cosign key it is the `cosign.pub` next to it and every image policy that pins that public key, `policies/verify.yaml: public key (ECDSA P-256), pinned by Kyverno ClusterPolicy verify-images`: whoever has the key and its passphrase signs images those policies admit. The GitHub match is reported in the attribution instead, because it is not a file. When nothing matches the line says so; the key may still be trusted by hosts, certificates and accounts that were not scanned.
- **revoke** -- the settings page where its owner revokes it by hand, or `--revoke` to let patty do it. A kind no API can revoke gets its owner's rotation procedure instead. [Revoking](#revoking) has both, per provider.
- **local** -- the credential is also configured on the machine running patty, and the line names the file or variable. Replace it there, or the next commit leaks it again. [Where credentials live locally](#where-credentials-live-locally) lists what is checked.
- **history** -- per repository, whether the token sits in branch history (yours to rewrite with [`git filter-repo`](https://github.com/newren/git-filter-repo) and force-push), only in pull request refs or in orphaned commits (only [GitHub Support](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository) can purge those).
- **audit** -- for providers that keep a usage log, where to look for what the credential was used for while it was exposed, and what the provider does on its own when it spots a leak. This line stays even for a key that is dead by now. [Auditing use](#auditing-use) has the list.

## Revoking

Each credential is revoked through its own provider's API. `--revoke` implies `--verify` and only ever submits credentials the provider just confirmed as active. It shows what it is about to revoke and asks; without a terminal it refuses unless `--yes` is given, so a cron job cannot revoke by accident.

```bash
patty acme --revoke                       # scan, verify, list the active credentials, ask, revoke
patty acme --revoke --yes                 # the same without the question
patty acme --revoke --ignore b492588d…    # leave one credential alone
patty revoke < tokens.txt                 # tokens you already have, one per line (or anywhere in the text)
```

Afterwards each credential is checked again and the outcome is recorded per credential in the report and the JSON (`"revocation": "revoked" | "pending"`).

One rule holds for every provider: a credential that is still configured on this machine (the *local* line) stops working for that tool the moment it is revoked. Have the replacement ready.

### GitHub

GitHub runs an unauthenticated endpoint for reporting leaked credentials, `POST /credentials/revoke`. Anyone who finds a token can submit it; GitHub revokes it and emails the owner. It accepts personal access tokens (classic and fine-grained), OAuth tokens, and GitHub App user-to-server and refresh tokens -- everything patty finds except installation tokens (`ghs_`), which expire within an hour anyway.

One side effect is called out in the confirmation list, because it is easy to miss: revoking an OAuth or GitHub App token (`gho_`, `ghu_`, `ghr_`) revokes the **whole authorization** of that application. Every token it holds for the user dies, including the one in use right now: revoke an old GitHub CLI token and `gh` is logged out on every machine until `gh auth login` is run again.

GitHub processes revocations asynchronously, so a token may still answer as *pending* in the follow-up check for a moment.

### GitLab

A personal access token revokes itself: `DELETE /api/v4/personal_access_tokens/self` with the token in `PRIVATE-TOKEN`, on the first candidate instance that accepts it; an instance that answers 401 is not the one that issued the token, and the next is tried. Before asking for confirmation patty reads the token with `GET …/self` on the same instances and shows the answer under it. Every other family is revoked by its owner, and the report says where: deploy tokens under the project's or group's *Settings → Repository → Deploy tokens*, runner tokens under *Settings → CI/CD → Runners*, trigger tokens under *Settings → CI/CD → Pipeline trigger tokens*, feed and incoming mail tokens under the user's *Access Tokens* page, agent tokens under the agent's *Access tokens*, application secrets under *Applications*, feature flag client tokens by regenerating the project's instance ID, SCIM tokens under the group's *SAML SSO* settings. GitLab is not a GitHub secret scanning partner: a token leaked into a GitHub repository is revoked by nobody but its owner.

### Slack

Slack tokens are revoked with [`auth.revoke`](https://api.slack.com/methods/auth.revoke), authenticated with the token itself; Slack does not notify anyone. Before asking for confirmation patty calls the method in its test mode (`test=1`), which answers exactly as the real call would without revoking anything, and shows that answer under each token.

Revoking a **bot token** deactivates the app's installation in that workspace: the app has to be reinstalled there to get a new token. Revoking a **user token** removes that user's authorization of the app in that workspace. Neither deletes the app, touches its installations in other workspaces, or deactivates its **app-level tokens**, **configuration tokens** or **incoming webhooks**; those are removed in the app's settings, and the report points there. Refresh tokens are accepted by `auth.revoke` but cannot be verified without rotating them, so `--revoke` never submits one; `patty revoke` does when given one.

### AWS

AWS has no endpoint for reporting a leaked key, so `--revoke` does the next best thing: it deactivates the key through [`iam:UpdateAccessKey`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html), signed with the key itself, on the IAM user the key belongs to. That works when the key pair is complete and its user may manage its own access keys; when it may not, the report says *this key is not allowed to deactivate itself* and points at the IAM console. A key that belongs to a role session or the root user, and any temporary key, cannot be handled this way. The key is set to *Inactive*, which its owner can undo; deleting it for good (`aws iam delete-access-key`) is left to them. There is no dry run.

By hand: IAM console → Users → the user → Security credentials → deactivate, then delete the key; or `aws iam update-access-key --access-key-id <id> --status Inactive` followed by `aws iam delete-access-key --access-key-id <id>`. Then check CloudTrail for what the key did since the commit that leaked it. A key that lands in a public GitHub repository is usually noticed by AWS within minutes, which attaches the `AWSCompromisedKeyQuarantine` policy to the user: that limits what the key may do (no new users, roles or instances) but does not deactivate it. Temporary keys (`ASIA`) expire on their own within hours; find and stop the process or role session that minted them, or use *Revoke sessions* on the role.

### Google Cloud

Google's OAuth tokens are revoked at [`POST https://oauth2.googleapis.com/revoke`](https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke) with the token as the form body; whoever holds an access or a refresh token may call it, no client secret is needed. Revoking either revokes the **whole grant** they belong to: every tool that signed in with it, `gcloud` after `gcloud auth login`, an application holding the refresh token, is signed out and has to sign in again, and the confirmation prompt warns about that. The endpoint has no rehearsal, so before asking for confirmation patty checks each token the way `--verify` does, tokeninfo for an access token and one refresh for a refresh token that came with its client, and shows whether there is a grant left to revoke; a token Google already rejects counts as revoked. By hand, an OAuth token is revoked by removing the application under the account's permissions, or with `gcloud auth revoke` on the machine that signed in.

Service account keys and API keys cannot be revoked by their holder, so `--revoke` never submits one. A service account key is disabled and then deleted by its owner: `gcloud iam service-accounts keys disable <key id> --iam-account <email>`, then `keys delete`; the finding's name is the key id and the account. An API key is deleted under APIs & Services → [Credentials](https://console.cloud.google.com/apis/credentials).

### Azure

Azure has no endpoint a holder could revoke a credential at, so `--revoke` never submits an Azure finding and the report carries the owner's procedures. A client secret is deleted under the app registration's *Certificates & secrets*, or with `az ad app credential delete --id <clientId> --key-id <keyId>`; the key id is not in the secret, `az ad app credential list --id <clientId>` shows it. Then check the Entra sign-in logs for the service principal since the commit date. A storage key is rotated under *Access keys*, or with `az storage account keys renew --account-name <name> --key primary|secondary`: the leaked one first, then the other, since both grant full access. A shared access signature cannot be revoked on its own: rotate the account key that signed it, or delete the stored access policy it is bound to. Azure is a GitHub secret scanning partner for client secrets and storage keys, but do not assume anything was disabled; `--verify` says.

### sops

Nothing can revoke an age identity or a PGP key, so the report carries the rotation procedure: remove the recipient from `.sops.yaml`, run `sops updatekeys` on every affected file, then `sops rotate -i` on each so the data key changes too, and for a PGP key publish a revocation certificate. Rotation protects future commits only. Every commit already encrypted to the old recipient stays decryptable by whoever holds the key, and only rewriting history (the *history* line) helps with those.

### Anthropic

Anthropic's API cannot revoke a key by itself, and its Admin API only manages API keys, not admin keys or OAuth tokens. With `ANTHROPIC_ADMIN_KEY` set to an [Admin API key](https://console.anthropic.com/settings/admin-keys) of the organization, `--revoke` lists the organization's API keys (`GET /v1/organizations/api_keys`, paginated), matches each leaked key against the partial hint Anthropic shows for every key (`sk-ant-api03-R2D…igAA`: the characters before and after the ellipsis are compared with the leaked value), and sets the one match to *inactive* (`POST /v1/organizations/api_keys/{id}`). Before asking for confirmation patty does the listing and matching only, and shows the result under each key. A key no hint matches belongs to another organization and is reported as *not in this organization*, not as revoked; a hint that fits more than one key is reported too, and nothing is touched. Without an admin key, `--revoke` says so and the report points at the [Console](https://console.anthropic.com/settings/keys). An inactive key can be reactivated in the Console; archiving it for good is left to the owner.

Admin keys are managed only in the Console. OAuth tokens belong to a Claude Code sign-in: run `claude auth logout` on the machine that signed in, or sign the session out on claude.ai; the access token expires on its own within hours, the refresh token does not.

### OpenAI

OpenAI's API cannot revoke a key by itself either. With `OPENAI_ADMIN_KEY` set to an [admin key](https://platform.openai.com/settings/organization/admin-keys) of the organization, `--revoke` finds a leaked admin key in the organization's admin key list (`GET /v1/organization/admin_api_keys`) and a leaked project or service account key in the key lists of every project, archived ones included (`GET /v1/organization/projects`, then `GET /v1/organization/projects/{id}/api_keys`), matching each against the redacted value OpenAI shows for every key (`sk-abc...def`), and deletes the one match (`DELETE` on the same path). As with Anthropic, the dry run before the confirmation lists and matches only; a key no entry matches is *not in this organization*; an ambiguous match deletes nothing. OpenAI may refuse to delete a service account's key on its own, in which case deleting the service account under the project's settings removes it. Deletion is final. Legacy user keys (`sk-` and twenty characters on either side of the marker) are not listed by the Admin API and are revoked under the owner's [API keys](https://platform.openai.com/api-keys).

### Grafana

Nothing here is revocable by the holder: deleting a service account token needs `serviceaccounts:write`, deleting a Cloud token `accesspolicies:delete`, which the leaked token itself rarely has, so `--revoke` never submits a Grafana finding. The report points at the instance's *Administration → Service accounts* (where migrated API keys live too since Grafana 9.1, *Administration → API keys* before that) and, for a Cloud token, at the org's access policies page on grafana.com, with the org taken from the attribution. Grafana Cloud is a GitHub secret scanning partner for `glc_` tokens and revokes ones found in public repositories on its own; nobody does that for service account tokens or API keys.

### PagerDuty

PagerDuty's API revokes neither kind. A general access key is deleted under *Integrations → Developer Tools → API Access Keys* of the account (the key does not name the account's subdomain; `--verify` names its users), a user key under *My Profile → User Settings → API Access*. A routing key is regenerated on the service it belongs to, under *Integrations*; until then anyone holding it can page the on-call indefinitely, and afterwards Alertmanager, or whatever else sends events with it, needs the new key.

### npm

A token revokes itself: `DELETE /-/npm/v1/tokens/token/<token>` with the token as bearer, the request `npm token revoke` makes; a registry that only takes the record's key gets a second `DELETE` with the key the token list shows for it. Before asking for confirmation patty runs the same `whoami` and token lookup `--verify` does and shows the answer under the token. For revoking by hand the report points at the account's tokens page (`https://www.npmjs.com/settings/<user>/tokens`, with the user `--verify` names) and, for a token found on an `.npmrc` line for a private registry, at that registry's settings. npm is a GitHub secret scanning partner and revokes tokens found in public repositories and published packages on its own.

### Kubernetes

Kubernetes has no revocation API at all, so `--revoke` never submits a Kubernetes finding and each kind carries its procedure. A client certificate stays valid until it expires or the cluster's CA is rotated; Kubernetes has no certificate revocation, so until then the identity is live. A legacy service account token dies with its Secret (`kubectl delete secret <name> -n <namespace>`), a bound one with its ServiceAccount, after which the workloads using it need a restart. A basic auth user is removed from the API server's basic-auth file. A plaintext Secret manifest is deleted and recreated in every cluster it was applied to, with new material, then taken out of git in favour of sops or an external secrets operator.

### Private keys

No one issues a private key, so no one revokes it: `--revoke` never submits one and the report carries the owner's procedures. An SSH key is deleted from the account's [SSH keys](https://github.com/settings/keys), or from the repository's *Settings → Deploy keys* when the verification says a deploy key accepts it, and its public key removed from every `authorized_keys` that lists it; until then anyone with an unencrypted key can push, or log in, as its owner. A TLS certificate cannot be recalled from the browsers, clients and clusters that trust it. Reissue the certificate with a new key, revoke the old one at the CA so that revocation-checking clients stop trusting it, and rotate every server, load balancer and Kubernetes Secret that holds the old key; the *matches* line names the certificate and where it was committed. A cosign key is not revoked either: generate a new pair (`cosign generate-key-pair`), re-sign the images that matter, replace `cosign.pub` and every Kyverno or ClusterImagePolicy that pins the old key, or move to keyless signing; every signature made with the old key stays valid for as long as some policy pins it.

### Container registries

Only a Docker Hub personal access token can be revoked through an API, and only by itself: `--revoke` logs in with the token (`POST /v2/users/login` on hub.docker.com, which answers with a JWT), lists the account's tokens (`GET /v2/access-tokens`), finds the leaked one, and sets it inactive (`PATCH /v2/access-tokens/{uuid}` with `{"is_active": false}`). Docker Hub lists tokens without their values, so the leaked token is matched by its value or redacted hint when the list shows one, else as the account's only active token, else as the only token used within the last minutes, which was the login patty just made; when none of that singles it out, nothing is touched and the report points at the [security settings](https://hub.docker.com/settings/security). Before asking for confirmation patty does the login and the matching only, and shows the result under the token. A read-only token (`repo:read`, `repo:public_read`) may not manage tokens and is reported as such. An inactive token can be reactivated by its owner; deleting it is left to them.

Everything else is rotated by hand, and the report says where: Docker Hub passwords and organization access tokens in the account's or organization's settings; Quay robot tokens under the organization's *Robot Accounts* (regenerate) and OAuth tokens under the user's *Applications*; Azure tokens with `az acr token credential delete -r <registry> -n <token> --password1` or, for the admin user, *Access keys → Regenerate*; ghcr.io logins by revoking the GitHub token that is their password; Google logins by deleting the service account key; Harbor logins under the project's *Robot Accounts*; any other registry's login by changing the user's password. An ECR password expires within twelve hours on its own; the IAM credentials that minted it are what needs rotating. A pull secret found in a Helm chart or GitOps repository is also installed in every cluster that deployed it: rotate it there too.

## Where credentials live locally

After the scan, patty checks the machine it runs on for the credentials it found, and the *local* line names the file or variable. Only fingerprints of key ids and tokens are compared; the values never leave those files. `.env` files in the working directory are checked for every provider.

| Provider | Checked |
|----------|---------|
| GitHub | `~/.config/gh/hosts.yml`, `~/.config/hub`, Copilot's `hosts.json` and `apps.json`, `~/.config/git/credentials`, `~/.git-credentials`, `~/.netrc`, `~/.gitconfig`, `GITHUB_TOKEN`, `GH_TOKEN`, `GH_ENTERPRISE_TOKEN`, `GITHUB_ENTERPRISE_TOKEN`, and whatever `gh auth token` returns |
| GitLab | glab's `~/.config/glab-cli/config.yml`, `~/.netrc` and `~/.git-credentials` (a GitLab token as the password of a GitLab host), `GITLAB_TOKEN`, `GITLAB_PRIVATE_TOKEN`, `CI_JOB_TOKEN` |
| Slack | `~/.slack/credentials.json`, `SLACK_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_USER_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_WEBHOOK_URL` |
| AWS | `~/.aws/credentials`, `~/.aws/config`, `~/.s3cfg`, rclone's `rclone.conf`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| Google Cloud | the file `GOOGLE_APPLICATION_CREDENTIALS` names, `CLOUDSDK_AUTH_ACCESS_TOKEN`, and the `application_default_credentials.json` and `legacy_credentials/*/adc.json` gcloud writes under `~/.config/gcloud`; gcloud's `credentials.db` is not opened |
| Azure | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` and their `ARM_` twins, `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_KEY`, `AZURE_STORAGE_CONNECTION_STRING`, `AZURE_STORAGE_SAS_TOKEN`, and the CLI's `~/.azure/service_principal_entries.json` and `~/.azure/msal_token_cache.json` |
| sops | `~/.config/sops/age/keys.txt` (on macOS also `~/Library/Application Support/sops/age/keys.txt`), `SOPS_AGE_KEY`, and the file `SOPS_AGE_KEY_FILE` points at. PGP keys live in the GnuPG keyring, which is not a text file and is not read; `gpg --list-secret-keys` shows whether a reported fingerprint is on this machine |
| Anthropic | `ANTHROPIC_API_KEY`, `ANTHROPIC_ADMIN_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, Claude Code's `~/.claude/.credentials.json` and `~/.claude.json`, opencode's `~/.config/opencode/auth.json` |
| OpenAI | `OPENAI_API_KEY`, `OPENAI_ADMIN_KEY`, Codex's `~/.codex/auth.json` (which mostly holds a sign-in, not a key; only a key found there is compared), opencode's `auth.json` |
| Grafana | `GRAFANA_API_KEY`, `GRAFANA_TOKEN`, `GRAFANA_SERVICE_ACCOUNT_TOKEN`, `GRAFANA_CLOUD_API_KEY`, `GRAFANA_CLOUD_ACCESS_POLICY_TOKEN`, and the MCP server configurations of Claude Code (`~/.claude.json`) and Claude Desktop (`~/.config/Claude/claude_desktop_config.json`), whose env blocks often hold a Grafana token |
| PagerDuty | `PAGERDUTY_TOKEN`, `PAGERDUTY_API_KEY`, `PD_API_KEY`, `PAGERDUTY_USER_TOKEN`, `PAGERDUTY_ROUTING_KEY`, and the pd CLI's `~/.config/pd/config.yaml` |
| npm | `~/.npmrc` and the project's `.npmrc` in the working directory, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `NPM_CONFIG__AUTH` |
| Kubernetes | `~/.kube/config`, `~/.config/kube/config` and every file `KUBECONFIG` lists; only certificate and token fingerprints are compared |
| Private keys | every file under `~/.ssh/` and `~/.sigstore/`, and `SSH_PRIVATE_KEY`, `COSIGN_KEY`, `COSIGN_PRIVATE_KEY`; a variable that holds a path or a KMS URI instead of a key matches nothing |
| Container registries | `~/.docker/config.json`, podman's `~/.config/containers/auth.json` and the file `REGISTRY_AUTH_FILE` points at, helm's `~/.config/helm/registry/config.json` and `HELM_REGISTRY_CONFIG`, and `DOCKER_PASSWORD`, `REGISTRY_PASSWORD`, `QUAY_PASSWORD`, `ACR_PASSWORD`, `CR_PAT`. A login is compared by host and user, so a variable holding a bare password only matches when that password is a Docker Hub token; a config entry that names a `credsStore` or credential helper keeps its secret in the OS keychain, which is not read |

## Auditing use

The *audit* line says where to look for what a credential was used for while it was exposed, from the commit date on, and what the provider does on its own when it spots a leak:

- **AWS** -- CloudTrail.
- **Google Cloud** -- the Cloud Audit Logs, and for an API key the API's metrics under APIs & Services. Google disables a service account key it finds in a public repository only when the organization policy `iam.serviceAccountKeyExposureResponse` is set to `DISABLE_KEY`; the default is to wait for abuse.
- **Azure** -- the Entra sign-in logs of the service principal, and the storage account's diagnostic logs. Azure is a secret scanning partner for client secrets and storage keys, but nothing says a leaked one was disabled.
- **Anthropic and OpenAI** -- the usage page of their console, filtered by key. Both are GitHub secret scanning partners and disable keys found in public repositories on their own (OpenAI also emails the owner), so a key from public history is probably already dead; `--verify` confirms.
- **GitLab** -- `--verify` shows when a personal access token was last used; the instance's audit events list what it did since the commit date. GitLab is not a GitHub secret scanning partner: nobody revokes a leaked GitLab token but its owner.
- **Grafana** -- the service account's token list shows when each token was last used, and the instance's access log has the requests. Grafana Cloud is a secret scanning partner for `glc_` tokens and revokes them; nobody revokes service account tokens or API keys on their own.
- **PagerDuty** -- the account's audit trail for API keys, the service's incidents since the commit date for a routing key. PagerDuty is not a secret scanning partner, and gitleaks has no rule for its keys.
- **npm** -- the account's packages for versions published since the commit date (`npm view <pkg> time`). npm is a secret scanning partner and revokes tokens found in public repositories and published packages.
- **Kubernetes** -- the API server's audit log, for requests by the identity since the commit date.
- **SSH keys** -- the key's last-used date under the account's SSH keys and the account's security log, and on servers the sshd log.
- **TLS keys** -- the CA's issuance records and certificate transparency logs (crt.sh), for certificates on the key that nobody requested.
- **cosign keys** -- the Rekor transparency log (`rekor-cli search --public-key cosign.pub --pki-format x509`).

## Verifying against API servers

`--verify` sends a Kubernetes credential to one place only: the API server named in the kubeconfig it was found in, as one `GET /version` with the credential (a TLS client certificate, an `Authorization: Bearer` header, or HTTP Basic). The server's audit log will show that request, under the leaked identity, from the machine running patty. The kubeconfig's `certificate-authority-data` is used to trust the server, else `insecure-skip-tls-verify` if it says so, else the system roots. A credential without a server (a bare service account token, a Secret manifest) is not sent anywhere.

A repository can name any server it likes, so patty refuses to contact servers that are not `https`, and servers on private, loopback or link-local addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, their IPv6 equivalents, and any hostname that resolves there), reporting them as *unknown* with the reason. `--verify-private-servers` lifts that restriction for the case where patty runs inside the network the kubeconfig belongs to, and is the operator's decision, never the repository's.

## Instances a token does not name

A Grafana service account token, a Grafana API key and every GitLab token are accepted by exactly one instance, and the token does not say which. `--verify` therefore tries candidates, in this order:

1. The instances the operator named with `--grafana-url` or `--gitlab-url` (repeatable) or in `GRAFANA_URL` and `GITLAB_URL` (comma- or space-separated). They are contacted as given, plain http included: naming one is the operator's decision. For GitLab, gitlab.com is always among them.
2. The hosts the scanned content itself names: a host with a `grafana` or `gitlab` label (`grafana.example.com`, `acme.grafana.net`, `gitlab.example.com`) anywhere in the scanned repository or directory, the decoded values of Secret manifests included, with the scheme and port it was written with. Only a host under a public top-level domain counts: `grafana.yaml` is a file, `grafana.local` an mDNS name and `grafana.example.com-tls` a Secret; an instance under an internal domain is named with `--grafana-url` or `--gitlab-url`. The hosts named in the same object as the token come first. The vendor's own sites (grafana.com, docs.gitlab.com) and GitHub Pages (grafana.github.io) are not instances. Discovered hosts are subject to the same restrictions as [API servers](#verifying-against-api-servers): `https` only, and never on a private network unless `--verify-private-servers` is given.

The first instance that accepts the credential settles it as *active*. It is *revoked* only when every candidate rejected it explicitly, each instance named in the detail; a mix of rejections and instances that could not be asked is *unknown*, since the instance that would have accepted it may be the one that could not be asked. A Grafana token with no candidate at all is *unverifiable* with the hint to pass `--grafana-url`. Instances are only discovered during a scan: `patty revoke` has none and relies on the flags and, for GitLab, gitlab.com. A private npm registry named on an `.npmrc` line is contacted under the same restrictions.

## Verifying SSH keys against GitHub

`--verify` offers an unencrypted SSH key to `github.com:22` exactly once: one SSH connection as user `git`, authenticating with the key, with no session, no command and no shell; the connection is closed as soon as GitHub has answered the authentication. GitHub's answer says whether some account or deploy key still carries the key, which is the whole question. Before the key is offered, the server's host key is checked against GitHub's published fingerprints, read from `https://api.github.com/meta` once per run when that can be reached and embedded in patty otherwise; a server presenting any other host key is refused and the key is reported as *unknown*. The account's security log will show the authentication, from the machine running patty. Encrypted SSH keys, TLS keys and cosign keys are not offered to anyone.

Independently of `--verify`, and only for repositories that hold an SSH key, patty fetches `https://github.com/<login>.keys` for the GitHub logins it can read from the repository's commits (noreply author addresses) and, with a token, from its contributors, at most fifty per repository and once per login and run. Those files list the public keys an account has registered and are public; the request names the login, not the key, and nothing found in the repository is sent.

## Fingerprints

Every credential is shown with a **fingerprint** (`fp b492588d8d3ffbbb`): the first 16 hex characters of its SHA-256. It identifies a token in logs and reports without revealing it, and `--ignore b492588d8d3ffbbb,58b0d6ffe3821055` keeps tokens you have already dealt with out of future reports. `--ignore` also takes a kind, `--ignore kubernetes-secret-manifest`, to leave a whole family out.

## What leaves your machine

Without `--verify` or `--revoke`, nothing. The credentials patty finds are not sent anywhere unless you ask for that. With `--verify`, each found credential goes to its provider once, as listed below; `--revoke` and `patty revoke` add the revocation requests. Age identities, PGP keys, Anthropic refresh tokens, PagerDuty routing keys, GitLab tokens other than personal access, runner and deploy tokens, encrypted SSH keys, TLS keys and cosign keys are never sent anywhere, with or without `--verify`: there is no one to ask, or asking would have consequences.

### GitHub

`--verify` sends a token to `GET /user`, or `GET /installation/repositories` for an app installation token. `--revoke` and `patty revoke` send it to `POST /credentials/revoke`.

### GitLab

A personal access token makes one `GET /api/v4/personal_access_tokens/self` per candidate instance, with the token in `PRIVATE-TOKEN`, until one accepts it; a runner token one `POST /api/v4/runners/verify` per instance with the token as form data, the request every runner makes on start; a deploy token, together with its username, one `GET /jwt/auth?service=container_registry` per instance as HTTP Basic, which requests no scope and reads nothing. Job, trigger, feed, incoming mail, agent, application, feature flag and SCIM tokens are not sent anywhere. `--revoke` sends one `DELETE /api/v4/personal_access_tokens/self` per instance until one accepts it, after the same `GET`. [Instances a token does not name](#instances-a-token-does-not-name) says which instances those are.

### Slack

`--verify` sends a token to `POST auth.test`. A webhook URL receives one `POST` with an empty JSON object, which Slack rejects without posting anything. `--revoke` sends a token to `POST auth.revoke`, first in test mode and then, after confirmation, for real.

### AWS

A key pair signs one `sts:GetCallerIdentity` call, which needs no permission and is not retried; it is recorded in CloudTrail in the key owner's account, so the owner can see that the key was checked. A key id without its secret is not sent anywhere. `--revoke` signs one more `sts:GetCallerIdentity` and one `iam:UpdateAccessKey`.

### Google Cloud

A service account key signs one one-minute JWT assertion, sent to `POST https://oauth2.googleapis.com/token` (or the `token_uri` the key file names, when that is an https URL under googleapis.com); the private key itself is never sent, and the access token Google answers with is discarded. An access token goes to `POST https://oauth2.googleapis.com/tokeninfo` once. A refresh token found with its OAuth client makes one `grant_type=refresh_token` request to the token endpoint, with that client id and secret, and the access token it mints is discarded; a bare refresh token is not sent anywhere. An API key makes one `GET https://www.googleapis.com/discovery/v1/apis?key=…`, which lists public API descriptions and touches no project data. `--revoke` sends OAuth access and refresh tokens to `POST https://oauth2.googleapis.com/revoke`, after the same tokeninfo or refresh check as the rehearsal.

### Azure

A client secret found with its tenant and client id makes one client-credentials request to `POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` for the Graph `.default` scope, and the token Entra answers with is discarded; the request appears in the tenant's sign-in logs under the service principal. A storage account key signs one `GET https://<account>.blob.core.windows.net/?comp=list` with Shared Key, which lists the container names and nothing in them; the key itself is never sent, only the HMAC it produces. A shared access signature found with its URL makes one `HEAD` of exactly that URL, and only when the host is an https Azure Storage endpoint (`core.windows.net`, `core.chinacloudapi.cn`, `core.usgovcloudapi.net`). An expired signature, a bare token, and a secret or key without its companion are not sent anywhere. `--revoke` sends nothing to Azure.

### Anthropic

API keys and OAuth access tokens make one `GET /v1/models` (with the `anthropic-beta: oauth-2025-04-20` header for OAuth tokens, which the API requires); admin keys make one `GET /v1/organizations/me`. When `ANTHROPIC_ADMIN_KEY` is set, the organization's key list is fetched once per run with that key so the report can name the leaked keys; the leaked keys themselves are compared locally against the hints in that list and are not sent to the Admin API. `--revoke` then sends one status change per matched key, with the admin key.

### OpenAI

Keys make one `GET /v1/models`; admin keys make one `GET /v1/organization/admin_api_keys`. When `OPENAI_ADMIN_KEY` is set, the organization's key lists are fetched once per run with that key, and the leaked keys are compared locally against the redacted values in them. `--revoke` then sends one deletion per matched key, with the admin key.

### Grafana

A service account token or API key makes one `GET /api/user` per candidate instance, with the token as bearer, until one accepts it; without a candidate it is not sent anywhere. A Cloud token makes one `GET https://grafana.com/api/v1/tokens?region=…` with the token as bearer and, when that lists the token, one `GET /api/v1/accesspolicies/<id>` to name its policy. `--revoke` sends nothing to Grafana.

### PagerDuty

An API key makes one `GET https://api.pagerduty.com/users/me` and, for a general access key, which has no user, one `GET /abilities`. A routing key is never sent anywhere, with or without `--verify`. `--revoke` sends nothing to PagerDuty.

### npm

A token makes one `GET /-/whoami` on its registry (registry.npmjs.org, or the private registry its `.npmrc` line named) with the token as bearer and, when accepted, one `GET /-/npm/v1/tokens` to find its own record. `--revoke` sends one `DELETE /-/npm/v1/tokens/token/<token>`, and a second one with the record's key when the registry does not take the value, after the same `whoami`.

### Kubernetes

A credential found in a kubeconfig makes one `GET /version` against the server that kubeconfig names, with the credential, subject to the restrictions in [verifying against API servers](#verifying-against-api-servers). A service account token found anywhere else, and a Secret manifest, are not sent anywhere. `--revoke` sends nothing to Kubernetes.

### Private keys

An unencrypted SSH key makes one SSH authentication to `github.com:22` as `git`, with no command, after the host key was matched against GitHub's published fingerprints. The `.keys` lookups described in [verifying SSH keys against GitHub](#verifying-ssh-keys-against-github) name logins, never keys, and the repository's contributors are listed through the GitHub API only when a token is available. `--revoke` sends nothing for a private key.

### Container registries

A login makes one anonymous `GET /v2/` on its registry, which answers with the address of its token service, and then one `GET` of that token service with the login as HTTP Basic and no scope; a registry that only speaks Basic gets the login at `/v2/` itself. No image, manifest or repository list is pulled or asked for. Docker Hub logins and tokens instead make one `POST /v2/users/login` on hub.docker.com, Quay OAuth tokens one `GET /api/v1/user/` on quay.io. A Docker Hub token without a username is not sent anywhere. `--revoke` logs in with a Docker Hub personal access token once more, lists the account's tokens with the JWT it gets, and sends one `PATCH` to deactivate the matched token.
