# Which credentials patty could check next

patty knows one credential family today: GitHub tokens. For each token it does five things, and every candidate below is measured against the same five:

1. **Detect** -- a fixed prefix and an exact shape, ideally with an offline checksum so a look-alike string is never reported.
2. **Attribute** -- say what the credential is and who it belongs to, offline where the format allows it.
3. **Verify** -- one harmless authenticated request that tells *active* from *revoked*, with what the credential gives access to.
4. **Recommend** -- where the owner revokes it, whether it is still configured on this machine, what its history needs.
5. **Revoke** -- an endpoint the *finder* of a credential may call, not only its owner. GitHub's `POST /credentials/revoke` is the model; few providers have one, but many let a token revoke itself.

## How the list was ranked

Three signals, in this order:

- **Do Timo or Giant Swarm use it?** Measured from what is configured on this machine (registries in `~/.docker/config.json`, AWS profiles, `~/.azure`, `~/.config/gcloud`, `~/.kube/config`, `~/.circleci`, `~/.config/sops/age`, `~/.claude`, `~/.codex`, `~/.config/.wrangler`), from a GitHub code search for credential-shaped environment variable names across the `giantswarm` organization (counts below), and from the team memory (`giantswarm/agent-memory`).
- **Does gitleaks have a rule, and how good is it?** A rule that matches a *prefix* (`xoxb-`, `AKIA`, `glpat-`) is one patty can adopt as-is and improve with a checksum. A rule that needs a *keyword* nearby (`(?i)cloudflare.{0,20}[a-z0-9_-]{40}`) tells you the format has no anchor; those are last or skipped.
- **Does GitHub secret scanning have a partner and a validity check for it?** A partner receives every public leak and is expected to revoke; a validity check means GitHub itself knows how to test the credential, so an endpoint exists.

Code search hits for `org:giantswarm` (September 2026, includes vendored code):

| Variable | Hits | Variable | Hits |
|---|---:|---|---:|
| `ANTHROPIC_API_KEY` | 1582 | `SLACK_TOKEN` + `SLACK_BOT_TOKEN` | 120 |
| `AWS_SECRET_ACCESS_KEY` | 1368 | `AZURE_CLIENT_SECRET` | 111 |
| `OPENAI_API_KEY` | 1288 | `OPSGENIE_API_KEY` | 61 |
| `PAGERDUTY_TOKEN` | 1078 | `NPM_TOKEN` | 35 |
| `GRAFANA_API_KEY` | 17 | `VAULT_TOKEN` | 15 |
| `ACR_PASSWORD` | 13 | `GOOGLE_APPLICATION_CREDENTIALS` | 4 |

Nothing for `CLOUDFLARE_API_TOKEN`, `TF_TOKEN`, `SENTRY_AUTH_TOKEN`, `DATADOG_API_KEY`, `HCLOUD_TOKEN`, `TAILSCALE_AUTHKEY`, `INCIDENT_IO_API_KEY`. Secret scanning alerts could not be used as a signal: it is disabled on the `giantswarm` and `teemow` repositories that were checked.

## The list

| # | Credential | Timo | Giant Swarm | gitleaks rule | GitHub partner / validity | Offline check | Verify | Holder can revoke |
|--:|---|:-:|:-:|---|:-:|---|---|---|
| 1 | [Slack tokens and webhooks](#1-slack) | ✓ | ✓✓ | prefix (7 rules) | ✓ / ✓ | prefix + team id | `auth.test` | **yes**, `auth.revoke` |
| 2 | [AWS access keys](#2-aws-access-keys) | ✓✓ | ✓✓ | prefix (key id only) | ✓ / ✓ | account id from key id | STS `GetCallerIdentity` | with the key's own IAM rights |
| 3 | [Anthropic keys](#3-anthropic) | ✓✓ | ✓✓ | prefix (`api03`, `admin01`) | ✓ / ✓ | fixed `AA` suffix | `GET /v1/models` | with an admin key |
| 4 | [OpenAI keys](#4-openai) | ✓ | ✓ | prefix + marker | ✓ / ✓ | `T3BlbkFJ` marker | `GET /v1/models` | no |
| 5 | [Azure: Entra client secrets, storage keys, ACR](#5-azure) | ✓ | ✓✓ | shape (`Q~`) | ✓ / storage only | none | client-credentials grant | no |
| 6 | [Google Cloud: service account keys, OAuth tokens, API keys](#6-google-cloud) | ✓ | ✓ | `AIza`, PEM | ✓ / ✓ | email, project from JSON | signed JWT → token endpoint | **yes** for OAuth tokens |
| 7 | [Container registry credentials](#7-container-registry-credentials) | ✓✓ | ✓✓ | none | Docker ✓ / ✗ | host from config | registry `/v2/` token dance | Docker Hub: yes |
| 8 | [Kubernetes: kubeconfigs, service account tokens, Secret manifests](#8-kubernetes) | ✓✓ | ✓✓ | yaml, jwt, PEM | ✗ | JWT claims, server URL | `GET /version` on the server | no (rotate) |
| 9 | [age and PGP private keys (sops)](#9-age-and-pgp-keys-sops) | ✓ | ✓ | prefix (age), PEM | ✗ | Bech32 checksum; recipient match | none | no (re-encrypt) |
| 10 | [SSH, TLS and cosign private keys](#10-ssh-tls-and-cosign-private-keys) | ✓ | ✓ | PEM | ✗ | fingerprint vs `github.com/user.keys` | `ssh -T git@github.com` | no |
| 11 | [Grafana tokens](#11-grafana) | ✓ | ✓✓ | prefix (3 rules) | ✓ / ✓ (cloud) | **CRC32** in `glsa_`; org in `glc_` | instance API | no (admin) |
| 12 | [PagerDuty keys](#12-pagerduty) | – | ✓✓ | **none** | ✗ / ✗ | prefix only | `GET /users/me` | no |
| 13 | [npm tokens](#13-npm) | ✓ | ✓ | prefix | ✓ / ✓ | – | `GET /-/whoami` | **yes** |
| 14 | [GitLab tokens](#14-gitlab) | – | ✓ | prefix | ✗ / ✓ | **CRC32** (routable) | `/personal_access_tokens/self` | **yes** |
| 15 | [Cloudflare tokens](#15-cloudflare) | ✓ | – | keyword | ✓ / ✗ | none | `/user/tokens/verify` | with the right scope |
| 16 | [HubSpot private app tokens](#16-hubspot) | – | ✓ | keyword (legacy) | ✓ / ✗ | `pat-<region>-` prefix | access-token-info | no |
| 17 | [Vault and Terraform tokens](#17-hashicorp-vault-and-terraform) | – | ✓ (legacy) | prefix | TF ✓ / ✓ | – | `lookup-self` | **yes** (both) |
| 18 | [1Password service account tokens](#18-1password) | ✓ | ✓ | prefix | ✗ / ✗ | payload decodes to account | `op whoami` | no |
| 19 | [incident.io and OpsGenie keys](#19-incidentio-and-opsgenie) | – | ✓ | none / keyword | ✗ | none | `/v1/identity`, `/v2/account` | no |
| 20 | [CircleCI tokens](#20-circleci) | ✓ | ✓ | **none** | ✓ / ✓ | new prefix only | `GET /api/v2/me` | no |
| 21 | [Sentry, PyPI, Telegram, Heroku](#21-lower-priority-personal-or-occasional) | ✓ | some | prefix | mixed | payload decodes | mixed | mixed |
| – | [Cross-cutting: JWTs, credentials in URLs, basic auth](#cross-cutting-jwts-credentials-in-urls-basic-auth) | | | jwt, curl | | claims, host | per issuer | |
| – | [Not worth it](#not-worth-it) | | | | | | | |

"Holder can revoke" means the leaked credential, or anyone who has it, can kill it without the owner's login. That is what makes `--revoke` possible.

---

## 1. Slack

**Why here.** Slack is Giant Swarm's alerting and agent surface: klaus-gateway mints per-turn tokens, Alertmanager and workflows post through webhooks, 103 mentions in the team memory, 120 code hits. Bot tokens end up in `.env` files and Helm values. Timo runs personal bots too.

**Detect.** Every family has a hard prefix, and the two numeric segments are team and app ids:

| Prefix | Kind | gitleaks rule |
|---|---|---|
| `xoxb-` | bot token | `slack-bot-token` |
| `xoxp-` | user token | `slack-user-token` |
| `xapp-1-` | app-level token (Socket Mode) | `slack-app-token` |
| `xoxe-` | refresh token (token rotation) | `slack-user-token` (shared pattern) |
| `xoxe.xoxb-` / `xoxe.xoxp-` | app configuration token | `slack-config-access-token` |
| `xwfp-` | workflow token, expires in 15 minutes | none |
| `https://hooks.slack.com/services/T…/B…/…` | incoming webhook | `slack-webhook-url` |

No checksum; the shape (`xoxb-` + digits + `-` + digits + `-` + 24 alphanumerics) is strict enough that false positives are rare. The team id (`T…`) in a webhook URL and the first digit group of a token identify the workspace offline.

**Verify.** `POST https://slack.com/api/auth.test` with `Authorization: Bearer <token>`. `ok: true` returns `team`, `user`, `bot_id`, `url` (the workspace); `invalid_auth` or `token_revoked` means dead, `account_inactive` means the workspace is gone. Rate tier 4, so verifying hundreds of tokens is fine. Scopes come from the `X-OAuth-Scopes` header, exactly like GitHub. For webhooks, `POST` an empty JSON object: a live webhook answers `400 invalid_payload` (nothing is posted), a dead one `404 no_service` or `no_team`.

**Recommend.**
- revoke: `https://api.slack.com/apps` → the app → *OAuth & Permissions* → *Revoke*, or for a user's own token `https://<workspace>.slack.com/apps/manage`; webhooks under *Incoming Webhooks*
- local: `~/.slack/credentials.json` (Slack CLI), `SLACK_TOKEN`, `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_WEBHOOK_URL`, `.env`
- history: same three cases as GitHub

**Revoke.** `POST https://slack.com/api/auth.revoke` with the token itself. No scopes needed, the token revokes itself, and `test=1` is a dry run. Works for bot and user tokens; a revoked bot token deactivates the bot user but leaves the app installed, so nobody's workflow breaks silently. App-level and configuration tokens have to be revoked in the app settings. Webhooks cannot be revoked by the holder. Slack is also a secret scanning partner and revokes public leaks itself.

---

## 2. AWS access keys

**Why here.** Timo's machine has 17 `aws_access_key_id` entries across giantswarm, adidas and personal profiles. Giant Swarm runs CAPA management clusters; `AWS_SECRET_ACCESS_KEY` has 1368 hits. This is the credential most likely to matter when found.

**Detect.** The access key id is `(AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}` (gitleaks `aws-access-token`). `AKIA` is a long-lived IAM user key, `ASIA` a temporary STS key that dies on its own. The secret access key is 40 characters of base64 with no anchor; gitleaks does not try. patty should: after finding a key id, look for a `[A-Za-z0-9/+]{40}` within the same object (typically the next line of `~/.aws/credentials`, a `.env`, a Terraform variable). A key id without a secret is still worth reporting, a pair is verifiable.

**Attribute offline.** The account id is encoded in the key id: strip the 4-character prefix, base32-decode the next 12 characters, shift right by 7 and mask, and out comes the 12-digit account number. patty can say *key in account 123456789012* without a network call, and Giant Swarm's `opsctl list installations` maps account ids to installations and customers.

**Verify.** `sts:GetCallerIdentity` with a SigV4-signed request. It needs no permissions and cannot be denied by policy, so a `200` with `Arn` (`arn:aws:iam::123456789012:user/ci-deployer`) means active, `InvalidClientTokenId` means deleted, `SignatureDoesNotMatch` means the id exists but the secret found next to it is wrong (or the key was rotated). With only a key id and *some* valid local credentials, `sts:GetAccessKeyInfo` returns the account id server-side. Either check writes a CloudTrail entry in the victim's account, which is a feature: the owner can see where the check came from.

**Recommend.**
- revoke: IAM → Users → *Security credentials*, or `aws iam update-access-key --access-key-id AKIA… --status Inactive` then `delete-access-key`; for root keys the account settings page
- local: `~/.aws/credentials`, `~/.aws/config` (`credential_process`, `sso_*` are fine), `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `~/.s3cfg`, `~/.config/rclone/rclone.conf`, `.env`
- history: as GitHub. Add: *check CloudTrail for use of this key since the commit date*

**Revoke.** No public reporting endpoint. `iam:UpdateAccessKey` on the key's own user is the only way a holder can deactivate it, and only when that user is allowed to manage its own keys, which many CI users are not. patty can try it and report `AccessDenied` honestly. When GitHub finds a key in a public repository, AWS attaches `AWSCompromisedKeyQuarantineV3` to the user, which blocks the expensive actions but does not deactivate the key; patty should say so rather than assume the key is dead.

---

## 3. Anthropic

**Why here.** Giant Swarm's agent platform, klaus, muster and the Backstage AI chat run on Anthropic keys; 1582 hits is the largest count of any variable. Timo has Claude Code's OAuth token on this machine.

**Detect.**

| Prefix | Kind | gitleaks rule |
|---|---|---|
| `sk-ant-api03-` + 93 chars + `AA` | API key (108 chars) | `anthropic-api-key` |
| `sk-ant-admin01-` + 93 chars + `AA` | Admin API key | `anthropic-admin-api-key` |
| `sk-ant-oat01-` | OAuth access token (Claude Code, Claude.ai) | **none** |
| `sk-ant-ort01-` | OAuth refresh token | **none** |

The trailing `AA` is fixed padding, a weak checksum but enough to reject a random `sk-ant-api03-` string in a test. The OAuth families are not in gitleaks at all and are the ones that sit in `~/.claude/.credentials.json` on every developer machine.

**Verify.** `GET https://api.anthropic.com/v1/models` with `x-api-key` and `anthropic-version: 2023-06-01`. `200` is active, `401 authentication_error` is dead, `403 permission_error` is active but scoped. An admin key answers `GET /v1/organizations/me` with the organization name. For OAuth tokens the same `/v1/models` call with `Authorization: Bearer` works; a refresh token is unverifiable without the client id, like GitHub's `ghr_`.

**Recommend.**
- revoke: `https://console.anthropic.com/settings/keys` (API keys), `/settings/admin-keys` (admin), Claude Code: `claude auth logout` or the Claude.ai sessions page
- local: `ANTHROPIC_API_KEY`, `ANTHROPIC_ADMIN_KEY`, `~/.claude/.credentials.json`, `.env`, `~/.config/opencode/auth.json`
- history: as GitHub

**Revoke.** With an admin key: `GET /v1/organizations/api_keys`, match the leaked key against each key's `partial_key_hint` (`sk-ant-api03-R2D…igAA` -- first 16 and last 4 characters), then `POST /v1/organizations/api_keys/{id}` with `{"status":"inactive"}`. patty can do this when `ANTHROPIC_ADMIN_KEY` is set, which covers the Giant Swarm case where the leaked key belongs to the company organization. Without one there is no public endpoint. Anthropic is a secret scanning partner and disables keys found in public repositories.

---

## 4. OpenAI

**Why here.** 1288 hits, mostly vendored SDKs and examples, but real keys exist for Backstage AI chat experiments. Timo has Codex on this machine (OAuth, not an API key).

**Detect.** Every OpenAI key contains `T3BlbkFJ`, which is base64 for `OpenAI`, at a fixed position: `sk-proj-…T3BlbkFJ…`, `sk-svcacct-…`, `sk-admin-…`, and the legacy `sk-[20 chars]T3BlbkFJ[20 chars]`. gitleaks `openai-api-key` uses exactly that. It is a marker, not a checksum, but it makes false positives practically impossible.

**Verify.** `GET https://api.openai.com/v1/models` with `Authorization: Bearer`. `200` active, `401 invalid_api_key` dead. The response header `openai-organization` names the org, `openai-project` the project. An admin key can call `GET /v1/organization/admin_api_keys` to list itself.

**Recommend.**
- revoke: `https://platform.openai.com/api-keys` (project keys), `/settings/organization/admin-keys` (admin)
- local: `OPENAI_API_KEY`, `~/.codex/auth.json` (OAuth; report but do not verify), `.env`
- history: as GitHub

**Revoke.** No holder endpoint. OpenAI is a partner and automatically disables keys found in public repositories, then emails the owner; patty should report that as *probably already disabled, confirm with --verify* for keys in public history.

---

## 5. Azure

**Why here.** Giant Swarm's registries `gsoci.azurecr.io` and `gsociprivate.azurecr.io` and the CAPZ management clusters are Azure; `AZURE_CLIENT_SECRET` has 111 hits, `ACR_PASSWORD` 13. Timo has `~/.azure`.

Three different credentials:

**Entra ID client secrets.** Shape `[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}`, 40 characters with `Q~` at position 4 (gitleaks `azure-ad-client-secret`). No checksum, no embedded id. A secret is useless without its tenant id and application (client) id, and so is verification, so patty has to look for two GUIDs in the same object (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `tenantId:`, `clientId:`, `ARM_TENANT_ID`). With all three: `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with `grant_type=client_credentials&scope=https://graph.microsoft.com/.default`. `200` is active; `AADSTS7000215` is *invalid client secret* (revoked or never valid); `AADSTS7000222` is *expired*; `AADSTS700016` means the app is not in that tenant. Only the pair is verifiable; a lone `Q~` string is reported as *shape match, needs tenant and client id*. Revoke at Entra admin center → App registrations → the app → *Certificates & secrets*, or `az ad app credential delete --id <app> --key-id <id>`. A holder cannot revoke unless the service principal itself has `Application.ReadWrite.OwnedBy`. Local: `~/.azure/service_principal_entries.json`, `AZURE_CLIENT_SECRET`, `ARM_CLIENT_SECRET`.

**Storage account keys.** 88 characters of base64 ending in `==`; gitleaks has nothing better than a keyword. GitHub has a validity check, so the shape is checkable: pair it with an account name from the same object (`AccountName=` in a connection string, `<name>.blob.core.windows.net`) and issue a signed `GET https://<name>.blob.core.windows.net/?comp=list`. Revoke: *Access keys* → *Rotate key*. Only worth doing after Entra secrets.

**ACR tokens and admin passwords.** `gsociprivate` pulls use scope-mapped ACR tokens (team memory: `gsociprivate-acr-scope-map-rename.md`). They have no distinctive format; they surface inside `~/.docker/config.json`, Kubernetes `imagePullSecrets` and CI variables, and are covered by [container registry credentials](#7-container-registry-credentials) below: verify against `https://gsociprivate.azurecr.io/v2/`, revoke with `az acr token credential delete`.

---

## 6. Google Cloud

**Why here.** Giant Swarm uses Vertex AI for Backstage's AI chat and Google Workspace APIs for the AE tooling. Timo has application default credentials and a `credentials.db` in `~/.config/gcloud`.

**Detect.** Three shapes:

| Shape | Kind | gitleaks rule |
|---|---|---|
| JSON with `"type": "service_account"`, `"private_key"`, `"client_email"` | service account key | `private-key` catches the PEM inside |
| `AIza[0-9A-Za-z_-]{35}` | API key | `gcp-api-key` |
| `ya29.[0-9A-Za-z_-]+` / `1//0[0-9A-Za-z_-]+` | OAuth access / refresh token | none |
| JSON with `"type": "authorized_user"`, `client_id`, `client_secret`, `refresh_token` | ADC user credentials | none |

**Attribute offline.** A service account key names itself: `client_email` (`deploy@my-project.iam.gserviceaccount.com`), `project_id`, `private_key_id`. That is better than most providers give after a network call.

**Verify.**
- Service account key: build a JWT (`iss` = `client_email`, `scope` = `https://www.googleapis.com/auth/cloud-platform`, `aud` = `https://oauth2.googleapis.com/token`, 60 s lifetime), sign it with the private key, `POST` it as `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`. `200` with an access token is active. `invalid_grant: Invalid JWT Signature` means the key was deleted, `account disabled` or `key disabled` say so, `invalid_grant: Not a valid email` means the account is gone.
- OAuth access token: `GET https://oauth2.googleapis.com/tokeninfo?access_token=…` returns `email`, `scope`, `expires_in`; `400 invalid_token` is dead. A refresh token needs its `client_id`/`client_secret`, which ADC files carry next to it.
- API key: keys are restricted per API, so the only generic test is a call that distinguishes *key not valid* (`400`, dead) from *this API is not enabled/allowed for this key* (`403`, alive); `GET https://www.googleapis.com/discovery/v1/apis?key=` works for that.

**Recommend.**
- revoke: `gcloud iam service-accounts keys disable <key-id> --iam-account <email>` then `delete`; API keys under *APIs & Services → Credentials*; user OAuth grants at `https://myaccount.google.com/permissions`
- local: `GOOGLE_APPLICATION_CREDENTIALS`, `~/.config/gcloud/application_default_credentials.json`, `~/.config/gcloud/legacy_credentials/*/adc.json`, `~/.config/gcloud/credentials.db` (sqlite, contains the same JSON)
- history: as GitHub. Add: Google can disable a service account key it finds in a public repository when the organization policy `iam.serviceAccountKeyExposureResponse` is set to `DISABLE_KEY`; the default is to wait for abuse, so do not count on it

**Revoke.** OAuth access and refresh tokens: `POST https://oauth2.googleapis.com/revoke?token=…` with the token itself. Revoking a refresh token kills the whole grant. That is a real holder-revoke and belongs in `--revoke`. Service account keys and API keys have no holder endpoint.

---

## 7. Container registry credentials

**Why here.** Timo's `~/.docker/config.json` holds logins for ten registries: `ghcr.io`, `gsoci.azurecr.io`, `gsociprivate.azurecr.io`, `quay.io`, Docker Hub, `registry.giantswarm.io`, `registry02.giantswarm.io`, `harbor.opendefense.cloud` and two personal ones. Giant Swarm's whole delivery path is OCI: images and charts on ACR, a decommissioned Quay history (`giantswarm-decommissioned-registry.md`), cosign-signed dev tags. Registry passwords are the credential most often pasted into a `values.yaml` as a pull secret. gitleaks has **no rule** for any of this.

**Detect.** Two containers and a few native formats:

- `~/.docker/config.json` shape anywhere in a repo: `"auths": {"<host>": {"auth": "<base64 user:password>"}}`. Decode, split on the first `:`, classify by host. Also `credsStore`/`credHelpers` entries mean *no secret here*.
- Kubernetes `kubernetes.io/dockerconfigjson` secrets: base64 inside base64; decode both layers.
- Docker Hub personal access tokens `dckr_pat_[A-Za-z0-9_-]{27}` and organization tokens `dckr_oat_…`. GitHub has a partner pattern for these.
- Quay robot tokens: 64 uppercase alphanumerics paired with a `<org>+<robot>` username. Quay OAuth tokens are 40 characters.
- GitHub tokens used as registry passwords (`ghcr.io`) are already caught; report them as *also a registry login*.

**Verify** without pulling anything: `GET https://<host>/v2/` returns `401` with `WWW-Authenticate: Bearer realm="…",service="…"`. Call the realm with HTTP basic auth and no `scope`. `200` with a token means the login works; `401` means dead. For ACR the response also lists the token's `access` scopes; for Quay, `GET https://quay.io/api/v1/user/` with the OAuth token names the user. Docker Hub: `POST https://hub.docker.com/v2/users/login` with username and the PAT as password returns a JWT on success.

**Recommend.**
- revoke: Docker Hub *Account settings → Personal access tokens*; Quay *Robot Accounts → Regenerate token*; ACR `az acr token credential delete -r <registry> -n <token> --password1` or *Access keys → Regenerate*; Harbor *Robot Accounts*; Giant Swarm's `registry*.giantswarm.io` is decommissioned, say so
- local: `~/.docker/config.json`, `~/.config/containers/auth.json` (podman), `~/.config/helm/registry/config.json`, `DOCKER_PASSWORD`, `QUAY_PASSWORD`, `ACR_PASSWORD`, `REGISTRY_PASSWORD`
- history: as GitHub. Add: a pull secret in a Helm chart is usually also in every cluster that installed the chart; rotate there too

**Revoke.** Docker Hub: log in with the PAT to get a JWT, `GET /v2/access-tokens` to find its own uuid, `PATCH /v2/access-tokens/{uuid}` with `is_active: false`. The token disables itself, provided it is not read-only. Quay and ACR need an account with admin rights; no holder endpoint.

---

## 8. Kubernetes

**Why here.** Giant Swarm sells Kubernetes; its GitOps repositories hold kubeconfigs for CI, service account tokens for Flux, and Secret manifests that were supposed to be encrypted. Timo's `~/.kube/config` has 73 `exec` users (good, those are Teleport) and three embedded client certificates (worth checking).

**Detect.**
- kubeconfig: YAML with `clusters[].cluster.server` and `users[].user` carrying `client-certificate-data` + `client-key-data`, `token`, or `password`. `exec` and `auth-provider` entries hold no secret and must not be reported.
- service account tokens: JWTs whose `iss` is `kubernetes/serviceaccount` or `https://kubernetes.default.svc…`, with `kubernetes.io/serviceaccount/namespace` and `…/service-account.name` claims (legacy) or a `kubernetes.io` object (bound tokens). gitleaks `jwt` catches the shape; patty adds the classification.
- Secret manifests: `kind: Secret` with `data:` (gitleaks `kubernetes-secret-yaml`). Decode every value and run the *whole detector* over it, because that is where the GitHub token, the registry password and the Slack webhook actually are. A Secret that is `sops`-encrypted (`sops:` block, `ENC[AES256_GCM…]` values) is not a leak and must be skipped.

**Attribute offline.** The JWT says namespace, service account name and, for bound tokens, `exp`. The kubeconfig says the server URL and, from the client certificate, the CN (`system:masters`?) and `Not After`. An expired token or certificate is reported as *expired*, no network needed.

**Verify.** Only when the kubeconfig carries the server URL: `GET <server>/version` with the credential. `200` is active; `401` is a rejected token; `403` with `system:anonymous` in the message means the certificate or token was not accepted. Clusters behind Teleport or on private networks answer with a connection error; report *unknown, server not reachable from here*, never *revoked*.

**Recommend.**
- revoke: service account tokens: `kubectl delete secret <name> -n <ns>` for legacy tokens, or delete and recreate the service account for bound tokens; client certificates **cannot be revoked** (Kubernetes has no CRL) -- the only fixes are waiting for `Not After` or rotating the cluster CA, so say that plainly
- local: `~/.kube/config`, `KUBECONFIG`, `~/.kube/cache`
- history: as GitHub

**Revoke.** None by the holder. A leaked `cluster-admin` certificate that is valid for ten years is the worst thing on this list; patty's job is to make that unmissable.

---

## 9. age and PGP keys (sops)

**Why here.** Giant Swarm encrypts GitOps secrets with sops; the muster broker clients and every `management-cluster-bases` installation carry `.sops.yaml` recipient lists. Timo has `~/.config/sops/age/keys.txt`. An age identity that reaches a repository decrypts every secret in every repository that lists it, forever.

**Detect.** `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}` (gitleaks `age-secret-key`). The string is **Bech32**, which carries a 6-character checksum; patty verifies it offline exactly as it verifies GitHub's CRC32, so a mangled or fabricated key is never reported. PGP: a `BEGIN PGP PRIVATE KEY BLOCK` armor header (gitleaks `private-key`); parse the packet to get the fingerprint and whether it is passphrase-protected.

**Attribute offline.** Derive the public key (`age1…`) from the secret, then look for that recipient in the scanned repositories: `.sops.yaml` `creation_rules`, the `sops.age[].recipient` metadata of every encrypted file. The report can say *decrypts 42 files in giantswarm/management-cluster-bases and 7 in giantswarm/muster*, which is the actual blast radius. Same for a PGP fingerprint in `sops.pgp[].fp`.

**Verify.** Nothing to call. The recipient match is the verification.

**Recommend.**
- revoke: remove the recipient from `.sops.yaml`, run `sops updatekeys` on every affected file, then `sops rotate` (`-r`) so the data key changes too; a PGP key gets a revocation certificate published to the keyserver
- local: `~/.config/sops/age/keys.txt`, `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, `~/.gnupg`
- history: as GitHub. Add: every commit that was encrypted to this recipient stays decryptable by whoever has the key, so rotating the data key only protects future commits

**Revoke.** None. This one is all recommendation.

---

## 10. SSH, TLS and cosign private keys

**Why here.** The most common private key in a repository is a developer's `id_ed25519` in a dotfiles repo or a CI deploy key in a Helm values file. Giant Swarm signs images with cosign (`architect-orb-cosign-dev-tags.md`); a leaked signing key forges provenance. Timo has `~/.sigstore`.

**Detect.** gitleaks `private-key` covers `BEGIN … PRIVATE KEY` armor headers for RSA, EC, OPENSSH, PGP, DSA and `ENCRYPTED SIGSTORE PRIVATE KEY`. patty should parse the block: algorithm, bits, whether it is passphrase-protected (an encrypted key is a much smaller leak), and the public key fingerprint.

**Attribute offline.** For SSH keys, fetch `https://github.com/<login>.keys` for every committer login in the repository and compare fingerprints. *This is jane's GitHub SSH key, added to her account* is a sentence no other scanner produces. TLS keys: match against certificates in the same repository (`BEGIN CERTIFICATE` blocks with the same public key) to name the hostnames. Cosign keys: match against `cosign.pub` files and the public keys pinned in Kyverno or policy-controller policies.

**Verify.** SSH keys against GitHub: `ssh -T git@github.com -i <key>` answers `Hi jane! You've successfully authenticated` for a live key and `Permission denied (publickey)` for a removed one. Nothing else is safe to try.

**Recommend.**
- revoke: `https://github.com/settings/keys` for SSH and GPG keys, the repository's *Deploy keys* page for deploy keys; TLS: reissue the certificate and revoke the old one at the CA; cosign: re-sign with a new key, update `cosign.pub` and the policies, or move to keyless signing
- local: `~/.ssh/`, `~/.sigstore`, `COSIGN_KEY`, `COSIGN_PASSWORD`
- history: as GitHub

**Revoke.** None by the holder.

---

## 11. Grafana

**Why here.** Giant Swarm's observability platform is Grafana on `giantswarm.grafana.net` with Mimir and Loki tenants (`observability-access.md`); QBR tooling uses service account tokens; 33 mentions. Timo uses the same.

**Detect.**

| Prefix | Kind | Offline | gitleaks rule |
|---|---|---|---|
| `glsa_` + 32 alphanumerics + `_` + 8 hex | service account token | the 8 hex chars are the **CRC32 of the secret**, same idea as GitHub's checksum | `grafana-service-account-token` |
| `glc_` + base64 | Grafana Cloud access policy token | the payload is JSON with `o` (org), `n` (token name), `k` (secret); org and name are readable offline | `grafana-cloud-api-token` |
| `eyJrIjoi…` | legacy API key (base64 JSON `{"k":…,"n":…,"id":…}`) | name and org id decode offline | `grafana-api-key` |

The `glsa_` checksum makes this the third family after GitHub and age with real offline verification.

**Verify.** A service account token is bound to one Grafana instance, and the token does not say which. patty should try the instances it can infer: `giantswarm.grafana.net` as the Giant Swarm default, any `grafana.*` host found in the same repository, and a `--grafana-url` flag. `GET <instance>/api/user` (or `/api/access-control/user/permissions`) with `Authorization: Bearer` answers `200` with the service account's login and org, `401` for a dead token. A `glc_` token is verified against the Cloud API, `GET https://grafana.com/api/v1/tokens?region=<region>` fails without the region, so use the token against the stack it names in `o` instead. Legacy API keys: same `/api/user` call.

**Recommend.**
- revoke: *Administration → Service accounts → the account → Tokens*; Cloud: *Security → Access Policies*; legacy keys under *API keys*
- local: `GRAFANA_API_KEY`, `GRAFANA_TOKEN`, `GRAFANA_CLOUD_API_KEY`, `~/.claude.json` MCP server configs (the QBR skill wires a read-only token there)
- history: as GitHub

**Revoke.** `DELETE /api/serviceaccounts/{id}/tokens/{tokenId}` needs `serviceaccounts:write`, which a normal token does not have; `DELETE https://grafana.com/api/v1/tokens/{id}` needs an access policy token with `accesspolicies:delete`. No holder revoke. Grafana Cloud is a partner and revokes public leaks.

---

## 12. PagerDuty

**Why here.** Giant Swarm's on-call runs on PagerDuty: Alertmanager routes to it (`alerting-pipeline.md`), the SRE skills read it, 1078 code hits. gitleaks has **no PagerDuty rule**, and GitHub only knows the OAuth tokens. That gap is the reason to do it.

**Detect.** Two kinds with different consequences:
- **REST API keys**, 20 characters. In practice general access keys begin with `y_` and user keys with `u+`, followed by 18 base64 characters. A user key acts as the user; a general key acts as the account.
- **Events API routing (integration) keys**, 32 hex characters, one per service integration. Anyone with one can page the on-call engineer at 3 a.m., indefinitely. They live in `alertmanager.yaml` `pagerduty_configs.routing_key` and `service_key`, so patty can detect them by *position*, which is more reliable than by shape.

**Verify.** REST keys: `GET https://api.pagerduty.com/users/me` with `Authorization: Token token=<key>` and `Accept: application/vnd.pagerduty+json;version=2`. `200` names the user; general keys get a `400`/`403` that still proves the key is accepted (a dead key is `401`). Routing keys **must not be verified**: the only test is sending an event, which pages a human. Report them as *unverifiable, treat as live*.

**Recommend.**
- revoke: *Integrations → API Access Keys* (general), *My Profile → User Settings → API Access* (user), the service's *Integrations* tab → regenerate the integration key (routing)
- local: `PAGERDUTY_TOKEN`, `PD_API_KEY`, `PAGERDUTY_ROUTING_KEY`, `pd` CLI config
- history: as GitHub

**Revoke.** No API for either kind. Owner only.

---

## 13. npm

**Why here.** Backstage is a Node monorepo; Giant Swarm publishes plugins; 35 hits. The Shai-Hulud worm harvested exactly these tokens from developer machines (`npm-supply-chain-shai-hulud.md`), so a token in a repository is a supply chain risk, not only a data risk.

**Detect.** `npm_[A-Za-z0-9]{36}` (gitleaks `npm-access-token`). Legacy UUID tokens only with a `_authToken=` anchor in `.npmrc`.

**Verify.** `GET https://registry.npmjs.org/-/whoami` with `Authorization: Bearer`. `200` returns the username; `401` is dead. `GET /-/npm/v1/tokens` lists the account's tokens with their first characters and `readonly`/`automation` flags, so patty can say *publish token* versus *read-only*.

**Recommend.**
- revoke: `https://www.npmjs.com/settings/<user>/tokens` or `npm token revoke <id>`
- local: `~/.npmrc` (`//registry.npmjs.org/:_authToken=`), project `.npmrc`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`
- history: as GitHub

**Revoke.** `DELETE https://registry.npmjs.org/-/npm/v1/tokens/token/<token>` with the token itself as bearer: the token revokes itself. npm is also a partner and revokes tokens found in public repositories and in published package tarballs.

---

## 14. GitLab

**Why here.** Low internal use (3 hits), but customers run GitLab, and it is the one provider with full parity to GitHub: checksum, self-verify, self-revoke. Cheap to add once the detector is generic.

**Detect.**

| Format | Kind | gitleaks rule |
|---|---|---|
| `glpat-[A-Za-z0-9_-]{20}` | personal access token (legacy) | `gitlab-pat` |
| `glpat-<base64url payload>.<2-char version><7 chars>` | routable PAT (GitLab 17.x+) | `gitlab-pat-routable` |
| `gldt-`, `glrt-`, `glcbt-`, `glptt-`, `glffct-`, `glimt-`, `glagent-` | deploy, runner, CI job, trigger, feature-flag, incoming-mail, agent tokens | one rule each |

The routable format ends in a **base36 CRC32** of the payload, and the payload encodes the instance and the token's id: offline verification and offline attribution in one.

**Verify.** `GET https://gitlab.com/api/v4/personal_access_tokens/self` with `PRIVATE-TOKEN` returns `scopes`, `user_id`, `expires_at`, `active`, `revoked`. Self-hosted instances: the routable payload names the instance, a `gitlab.*` host in the repository is the next guess, `--gitlab-url` the fallback.

**Recommend.**
- revoke: *User Settings → Access Tokens*
- local: `~/.config/glab-cli/config.yml`, `GITLAB_TOKEN`, `.netrc` for `gitlab.com`, `~/.git-credentials`
- history: as GitHub

**Revoke.** `DELETE /api/v4/personal_access_tokens/self`: any token can revoke itself, no scope needed. GitLab is not a partner, so nobody else will do it.

---

## 15. Cloudflare

**Why here.** Personal: Timo has Wrangler configured. Giant Swarm has no hits.

**Detect.** API tokens are 40 characters of `[A-Za-z0-9_-]` with no prefix; gitleaks matches only with `cloudflare` nearby. The legacy Global API Key is 37 hex characters, paired with an email. Detection stays keyword-anchored, which is why this is not higher.

**Verify.** `GET https://api.cloudflare.com/client/v4/user/tokens/verify` with `Authorization: Bearer`: the token verifies itself and returns its `id`, `status` (`active`, `disabled`, `expired`), `expires_on`. `GET /user` then names the account. Global key: `GET /user` with `X-Auth-Key` and `X-Auth-Email`.

**Recommend.** Revoke at `https://dash.cloudflare.com/profile/api-tokens`. Local: `~/.config/.wrangler/config/default.toml` (OAuth), `CLOUDFLARE_API_TOKEN`, `CF_API_KEY`.

**Revoke.** `DELETE /user/tokens/{id}` works only if the token has *API Tokens: Edit*; try it, report `403` honestly. Cloudflare is a partner.

---

## 16. HubSpot

**Why here.** Giant Swarm's events and marketing tooling reads HubSpot (the `gs-events` skills); 5 mentions, 3 hits. Nobody has this on a laptop, it lives in scripts and CI.

**Detect.** Private app access tokens are `pat-<region>-<uuid>`, e.g. `pat-na1-…` or `pat-eu1-…`. gitleaks only knows the legacy API-key UUID with a `hubspot` keyword; the prefix form is strictly better and missing there.

**Verify.** `POST https://api.hubapi.com/oauth/v2/private-apps/get/access-token-info` with the token in the body returns the hub id, user id, app id and scopes. `401` is dead.

**Recommend.** Revoke: the app's page → *Auth* → *Rotate and expire now* (UI only). Local: `HUBSPOT_ACCESS_TOKEN`, `HUBSPOT_API_KEY`, `.env`.

**Revoke.** None by the holder. HubSpot is a partner.

---

## 17. HashiCorp Vault and Terraform

**Why here.** Giant Swarm ran Vault in the pre-CAPI platform; 15 hits are mostly legacy. HCP Terraform: none. Included because both have holder revocation.

**Detect.** Vault `hvs.[A-Za-z0-9_-]{90,120}` (service), `hvb.` (batch), legacy `s.[a-z0-9]{24}`; gitleaks `vault-service-token`, `vault-batch-token`. HCP Terraform `[a-z0-9]{14}.atlasv1.[a-z0-9_-]{60,70}`; gitleaks `hashicorp-tf-api-token`.

**Verify.** Vault: needs the address, which is almost always next to the token (`VAULT_ADDR`); `GET /v1/auth/token/lookup-self` returns policies, TTL, display name. Terraform: `GET https://app.terraform.io/api/v2/account/details` returns the user and whether it is a service account.

**Recommend.** Vault tokens expire by TTL; report `expire_time`. Terraform: *User Settings → Tokens*. Local: `~/.vault-token`, `VAULT_TOKEN`, `~/.terraform.d/credentials.tfrc.json`, `TF_TOKEN_app_terraform_io`.

**Revoke.** Vault `POST /v1/auth/token/revoke-self`; Terraform `GET /api/v2/users/{id}/authentication-tokens` to find itself then `DELETE /api/v2/authentication-tokens/{id}`. Both by the token itself. Terraform is a partner.

---

## 18. 1Password

**Why here.** Both Timo and Giant Swarm use 1Password (`gs-base:1password`); service account tokens go into CI for `op run`.

**Detect.** `ops_eyJ[A-Za-z0-9+/]{250,}={0,3}` (gitleaks `1password-service-account-token`). The part after `ops_` is base64 JSON with `signInAddress`, `email` and a device UUID: account and identity decode offline. Secret Keys `A3-XXXXXX-…` (gitleaks `1password-secret-key`) are half of a human login and worth reporting as *combine with the master password*.

**Verify.** No REST endpoint takes the token directly; `OP_SERVICE_ACCOUNT_TOKEN=… op whoami` does, when the `op` CLI is installed. patty can shell out the way it already does for `gh auth token`.

**Recommend.** Revoke: *Developer → Service Accounts* in the admin console. Local: `OP_SERVICE_ACCOUNT_TOKEN`, `~/.config/op`.

**Revoke.** None by the holder.

---

## 19. incident.io and OpsGenie

**incident.io** (45 mentions, GS alerting migrated to it): API keys are opaque bearer tokens without a documented prefix, so detection needs a keyword (`INCIDENT_IO_API_KEY`, `incident.io` URL nearby). `GET https://api.incident.io/v1/identity` returns the key's name and roles. Revoke in *Settings → API keys*. No holder revoke. Do it once the keyword-anchored detector exists.

**OpsGenie** (61 hits, legacy): UUID keys, keyword-only; `GET https://api.opsgenie.com/v2/account` with `Authorization: GenieKey`. Giant Swarm has moved off it; report and point at the OpsGenie *API key management* page, nothing more.

---

## 20. CircleCI

**Why here.** Giant Swarm's CI (21 mentions), Timo's `~/.circleci/cli.yml` carries a token. gitleaks has **no rule**; the team memory notes why: a legacy personal token is a bare 40-hex string, indistinguishable from a commit SHA. Newer personal tokens carry a `CCIPAT_` prefix and can be detected outright; project tokens `CCIPRJ_`.

**Verify.** `GET https://circleci.com/api/v2/me` with `Circle-Token`. `200` names the user; `401` is dead. For 40-hex candidates, only try the ones that sit next to `CIRCLE_TOKEN`, `circleci`, or in `cli.yml`, otherwise every commit SHA in the repository gets a request.

**Recommend.** Revoke: `https://app.circleci.com/settings/user/tokens`. Local: `~/.circleci/cli.yml`, `CIRCLE_TOKEN`, `CIRCLECI_TOKEN`.

**Revoke.** None by the holder. CircleCI is a partner with a validity check on GitHub's side.

---

## 21. Lower priority: personal or occasional

- **Sentry** (13 mentions, Backstage plugin): `sntrys_eyJ…` organization tokens decode to `region_url` and `org` offline; `sntryu_[a-f0-9]{64}` user tokens. Verify `GET https://sentry.io/api/0/organizations/`. Revoke in the org's *Auth Tokens*. Partner with validity check.
- **PyPI** (occasional Python tooling): `pypi-AgEIcHlwaS5vcmc…` is a macaroon; its caveats decode offline to the user or the project it is scoped to. No harmless verify exists (the only API a token can call is upload). Revoke at `https://pypi.org/manage/account/token/`. PyPI is a partner and disables public leaks itself.
- **Telegram bot tokens** (Timo's bots): `[0-9]{8,10}:[A-Za-z0-9_-]{35}`; gitleaks needs `telegram` nearby, but the shape is strict enough alone. Verify `GET https://api.telegram.org/bot<token>/getMe`; revoke only through BotFather. Validity check on GitHub.
- **Heroku** (`~/.netrc` on this machine, ancient): `HRKU-AA[0-9A-Za-z_-]{58}` new keys, UUID legacy. Verify `GET https://api.heroku.com/account`; a token can `DELETE /oauth/authorizations/{id}` for itself.
- **Hugging Face** `hf_[A-Za-z]{34}`: `GET https://huggingface.co/api/whoami-v2`. Partner with validity check. Only if model work lands in a repository.

---

## Cross-cutting: JWTs, credentials in URLs, basic auth

Three detectors that are not a provider but multiply every provider's coverage:

**JWTs.** `ey…\.ey…\.…` (gitleaks `jwt`). Decode the header and claims offline: `iss`, `sub`, `aud`, `exp`. Then classify: Kubernetes service account (section 8), Entra (`login.microsoftonline.com`), Google (`accounts.google.com`), GitHub Actions OIDC (`token.actions.githubusercontent.com`), Backstage, Dex. An expired JWT is reported as *expired* with no network call; a live one is verified with the issuer's own check where one exists. Most JWTs in repositories are expired test fixtures; the value is in the few that are not.

**Credentials in URLs.** `https://user:secret@host/…` in git remotes, Helm repository configs, `requirements.txt`, `go.mod` replace directives, Alertmanager and Grafana datasource URLs. Split out the host and hand `secret` to the detectors above (`x-access-token:ghs_…@github.com` is a GitHub token, `robot:…@quay.io` a Quay token, `123456:glc_…@prometheus-prod-01.grafana.net` a Grafana Cloud token with its tenant id). gitleaks only covers the `curl -H Authorization:` form.

**Basic auth blobs.** `Authorization: Basic <base64>` in HTTP fixtures and `auth: <base64>` in docker configs. Decode and re-scan.

## Not worth it

Stripe, Twilio, SendGrid, Mailgun, Mailchimp, DigitalOcean, Linear, Notion, Datadog, New Relic, Okta, Shopify, Supabase, Vercel, Netlify, Fly.io, Pulumi, Postman, Discord, Mattermost: gitleaks has rules and GitHub has partners for most of them, but neither Timo nor Giant Swarm uses them. Teleport `tsh` certificates are valid for hours and never land in repositories. Google app passwords and IMAP credentials (`~/.msmtprc`) have no shape to detect. Add any of these only when a scan actually turns one up.

## What changes in patty

The order above is also the implementation order. The first step is the same for all of them: `detect` becomes a set of providers behind one interface -- `Find`, `Verify`, `Revocable`, `Revoke`, `RevokePage`, `LocalSources` -- with GitHub as the first implementation and the report, the `--verify`/`--revoke` flow and `localcreds` speaking in terms of *credentials* rather than *GitHub tokens*. Once Slack exists as the second provider, every further one is a file in `internal/detect/` plus a table row in this document.

Three behaviours from the GitHub provider carry over unchanged and should be kept as rules: only a `401` (or the provider's explicit *invalid credentials* code) counts as revoked, anything else is *unknown*; `--revoke` only submits credentials that were just verified as active; and nothing is sent anywhere without `--verify`.
