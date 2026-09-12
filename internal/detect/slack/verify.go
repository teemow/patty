package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

// apiResponse is the envelope every Web API method answers with.
type apiResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Team    string `json:"team"`
	TeamID  string `json:"team_id"`
	User    string `json:"user"`
	UserID  string `json:"user_id"`
	BotID   string `json:"bot_id"`
	Revoked bool   `json:"revoked"`
}

// Verify implements detect.Provider with one auth.test call, or an empty
// post for webhooks. Only Slack's explicit invalid-token answers count as
// revoked; anything else that is not a clean acceptance is unknown.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	switch tok.Kind {
	case KindRefresh:
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "refresh tokens are only exchanged for new access tokens; rotating one would replace the live token"}
	case KindWebhook:
		return p.verifyWebhook(ctx, tok.Value)
	default:
		return p.authTest(ctx, tok)
	}
}

func (p *Provider) authTest(ctx context.Context, tok detect.Token) detect.Verification {
	resp, err := p.call(ctx, "auth.test", tok.Value, "")
	if err != nil {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	var r apiResponse
	if json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &r) != nil {
		return detect.Verification{Status: detect.StatusUnknown, Detail: fmt.Sprintf("HTTP %d from auth.test", resp.StatusCode)}
	}
	switch {
	case r.OK:
		v := detect.Verification{Status: detect.StatusActive, Detail: describe(r, resp.Header)}
		for _, h := range []string{"X-OAuth-Client-Id", "X-OAuth-App-Id"} {
			if id := strings.TrimSpace(resp.Header.Get(h)); id != "" {
				v.ClientID = id
				break
			}
		}
		return v
	case r.Error == "invalid_auth", r.Error == "token_revoked":
		return detect.Verification{Status: detect.StatusRevoked}
	case r.Error == "account_inactive":
		return detect.Verification{Status: detect.StatusRevoked, Detail: "the user or bot account was deactivated"}
	case r.Error == "not_allowed_token_type" && (tok.Kind == KindApp || tok.Kind == KindConfig):
		// Slack checks the token before the method's token type, so this
		// answer means the token authenticated.
		return detect.Verification{Status: detect.StatusActive, Detail: "token accepted; auth.test does not describe this token type"}
	default:
		return detect.Verification{Status: detect.StatusUnknown, Detail: "auth.test: " + r.Error}
	}
}

// describe renders what auth.test says about a live token.
func describe(r apiResponse, h http.Header) string {
	who := "user " + r.User
	if r.BotID != "" {
		who = "bot " + r.User
	}
	detail := "team " + r.Team + ", " + who
	if scopes := strings.TrimSpace(h.Get("X-OAuth-Scopes")); scopes != "" {
		detail += ", scopes: " + strings.ReplaceAll(scopes, ",", ", ")
	}
	return detail
}

// verifyWebhook posts an empty JSON object, which Slack rejects as a bad
// payload if the webhook exists and as no_service if it does not. Nothing is
// ever posted to a channel.
func (p *Provider) verifyWebhook(ctx context.Context, url string) detect.Verification {
	target, ok := strings.CutPrefix(url, hooksOrigin)
	if !ok {
		return detect.Verification{Status: detect.StatusUnknown, Detail: "not a hooks.slack.com URL"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.HooksURL+target, strings.NewReader("{}"))
	if err != nil {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	body := strings.TrimSpace(string(detect.ReadBody(resp.Body, 4096)))
	switch {
	case resp.StatusCode == http.StatusBadRequest && (body == "invalid_payload" || body == "missing_text_or_fallback_or_attachments"):
		return detect.Verification{Status: detect.StatusActive, Detail: "webhook accepts messages"}
	case resp.StatusCode == http.StatusNotFound && (body == "no_service" || body == "no_team"),
		resp.StatusCode == http.StatusForbidden && body == "invalid_token":
		return detect.Verification{Status: detect.StatusRevoked}
	default:
		return detect.Verification{Status: detect.StatusUnknown, Detail: fmt.Sprintf("HTTP %d from the webhook: %s", resp.StatusCode, body)}
	}
}

// call posts one Web API method with the token as bearer credential and an
// optional form body.
func (p *Provider) call(ctx context.Context, method, token, form string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.APIURL+"/"+method, strings.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return detect.Do(p.Client, req)
}
