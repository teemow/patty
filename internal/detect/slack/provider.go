// Package slack is the Slack credential provider: bot, user, app-level,
// refresh and configuration tokens, and incoming webhook URLs.
//
// Slack tokens carry no checksum, so every family is matched on its exact
// shape. The numeric groups of a token name the workspace and the user or
// bot it was issued to; patty reports that offline. Verification is one
// auth.test call; revocation goes through auth.revoke with the token itself.
package slack

import (
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider for Slack.
type Provider struct {
	// APIURL is the Web API root, https://slack.com/api by default.
	APIURL string
	// HooksURL replaces the https://hooks.slack.com origin of webhook URLs
	// when verifying them; tests point it at a local server.
	HooksURL string
	Client   *http.Client
}

// hooksOrigin is where every incoming webhook URL points.
const hooksOrigin = "https://hooks.slack.com"

// appsPage is where an app's owner manages its tokens and webhooks.
const appsPage = "https://api.slack.com/apps"

// New returns a Provider against the public Slack API.
func New() *Provider {
	return &Provider{APIURL: "https://slack.com/api", HooksURL: hooksOrigin, Client: &http.Client{Timeout: 30 * time.Second}}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "Slack" }

// Kinds implements detect.Provider.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindBot, Description: "bot token", Revocable: true, RevokePage: appsPage,
			RevokeEffect: "the app loses its bot token in that workspace and has to be reinstalled there to get a new one"},
		{Kind: KindUser, Description: "user token", Revocable: true, RevokePage: "https://slack.com/apps/manage",
			RevokeEffect: "revokes this user's authorization of {app} in the workspace; the user has to authorize the app again"},
		{Kind: KindApp, Description: "app-level token", RevokePage: appsPage,
			RevokeNote: "app-level tokens are revoked under the app's Basic Information"},
		{Kind: KindRefresh, Description: "refresh token", Revocable: true, RevokePage: appsPage,
			RevokeEffect: "the app can no longer rotate the access token it belongs to"},
		{Kind: KindConfig, Description: "configuration token", RevokePage: appsPage,
			RevokeNote: "configuration and rotating tokens expire within twelve hours anyway, or delete the token pair in the app's settings"},
		{Kind: KindWebhook, Description: "incoming webhook", RevokePage: appsPage,
			RevokeNote: "webhooks are removed under the app's Incoming Webhooks, or in Workflow Builder for workflow webhooks"},
	}
}

// LocalSources implements detect.Provider: the environment variables the
// Slack SDKs read and the credentials file of the Slack CLI.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:       []string{"SLACK_TOKEN", "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN", "SLACK_WEBHOOK_URL"},
		HomeFiles: []string{".slack/credentials.json"},
	}
}
