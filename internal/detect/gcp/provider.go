// Package gcp is the Google Cloud credential provider: service account
// keys, the application default credentials of a signed-in user, the OAuth
// access and refresh tokens they produce, and API keys.
//
// A service account key is a JSON document, wherever it is embedded, and
// its own fields say whose it is; patty names it after the service account
// and the key id and keeps the private key apart. The bare tokens carry no
// checksum and no owner: an access token is a `ya29.` prefix and an
// undocumented body, a refresh token starts with `1//0`, an API key with
// `AIza`. Verification is one request each: a signed JWT to the token
// endpoint for a service account key, one tokeninfo call for an access
// token, one refresh for a refresh token that came with its client, one
// discovery call for an API key. Only OAuth tokens can be revoked by their
// holder, through Google's revoke endpoint, which takes the whole grant
// with them; a service account key and an API key are deleted by their
// owner in the Console.
package gcp

import (
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for Google Cloud.
type Provider struct {
	// TokenURL is the OAuth 2.0 token endpoint, https://oauth2.googleapis.com/token
	// by default; a service account key that names its own token_uri is
	// verified against that instead.
	TokenURL string
	// TokenInfoURL reports what an access token is, https://oauth2.googleapis.com/tokeninfo.
	TokenInfoURL string
	// RevokeURL revokes an OAuth grant, https://oauth2.googleapis.com/revoke.
	RevokeURL string
	// DiscoveryURL lists the Google APIs and accepts an API key,
	// https://www.googleapis.com/discovery/v1/apis.
	DiscoveryURL string
	Client       *http.Client
	// now is the clock the JWT a service account key signs is stamped with;
	// tests fix it.
	now func() time.Time
}

const (
	serviceAccountsPage = "https://console.cloud.google.com/iam-admin/serviceaccounts"
	credentialsPage     = "https://console.cloud.google.com/apis/credentials"
	// AccessTokenEnv is the variable gcloud reads an access token from
	// instead of signing in.
	AccessTokenEnv = "CLOUDSDK_AUTH_ACCESS_TOKEN"
	// CredentialsFileEnv names the file every Google SDK reads its
	// credentials from: a service account key or the ADC of a user.
	CredentialsFileEnv = "GOOGLE_APPLICATION_CREDENTIALS"
)

// auditNote is what to check after a key leaked, whether or not it is dead
// by now, and what Google does on its own when it spots one.
const auditNote = "check Cloud Audit Logs for use of the credential since the commit date; Google disables a service account key it finds in a public repository only when the organization policy iam.serviceAccountKeyExposureResponse is set to DISABLE_KEY, the default is to wait for abuse, so do not count on it"

// grantEffect is the side effect of revoking an OAuth token: the grant
// goes, not the token alone.
const grantEffect = "revokes the whole grant, not just this token: every tool that signed in with it ({app}, gcloud or an application) is signed out and has to sign in again"

// grantNote is the manual alternative for the OAuth families.
const grantNote = "or remove the application under https://myaccount.google.com/permissions, or run `gcloud auth revoke` on the machine that signed in"

// New returns a Provider against the public Google endpoints.
func New() *Provider {
	return &Provider{
		TokenURL:     "https://oauth2.googleapis.com/token",
		TokenInfoURL: "https://oauth2.googleapis.com/tokeninfo",
		RevokeURL:    "https://oauth2.googleapis.com/revoke",
		DiscoveryURL: "https://www.googleapis.com/discovery/v1/apis",
		Client:       &http.Client{Timeout: 30 * time.Second},
		now:          time.Now,
	}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "Google Cloud" }

// Kinds implements detect.Provider. The OAuth families are revocable by
// whoever holds them; a service account key and an API key only by their
// owner.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindServiceAccountKey, Description: "service account key (JSON)", RevokePage: serviceAccountsPage, PublicValue: true,
			RevokeNote: "`gcloud iam service-accounts keys disable <key id> --iam-account <email>`, then `keys delete` once nothing breaks; the key id and the account are the name of this finding",
			AuditNote:  auditNote},
		{Kind: KindUserCredentials, Description: "application default credentials of a user (authorized_user JSON)", Revocable: true,
			RevokeNote: grantNote, RevokeEffect: grantEffect, AuditNote: auditNote},
		{Kind: KindAccessToken, Description: "OAuth access token", Revocable: true,
			RevokeNote: grantNote + "; the token itself expires within an hour", RevokeEffect: grantEffect, AuditNote: auditNote},
		{Kind: KindRefreshToken, Description: "OAuth refresh token", Revocable: true,
			RevokeNote: grantNote, RevokeEffect: grantEffect, AuditNote: auditNote},
		{Kind: KindAPIKey, Description: "API key", RevokePage: credentialsPage,
			RevokeNote: "delete it under APIs & Services → Credentials, or `gcloud services api-keys delete <key id>`; an API key found in a public repository is not disabled by Google on its own",
			AuditNote:  "check the API's metrics under APIs & Services for calls with this key since the commit date"},
	}
}

// LocalSources implements detect.Provider: the file every SDK reads
// credentials from, gcloud's access token override, and the credential
// files gcloud writes after `gcloud auth login` and `gcloud auth
// application-default login`. gcloud also keeps tokens in a sqlite
// database, credentials.db, which is not opened.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{AccessTokenEnv},
		EnvFiles:    []string{CredentialsFileEnv},
		ConfigFiles: []string{"gcloud/application_default_credentials.json", "gcloud/legacy_credentials/*/adc.json"},
	}
}
