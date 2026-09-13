package pagerduty

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	mePath        = "/users/me"
	abilitiesPath = "/abilities"
	accept        = "application/vnd.pagerduty+json;version=2"
)

// Verify implements detect.Provider. An API key makes one GET /users/me: a
// user key answers with its user, a general access key is account-level
// and has no user, which PagerDuty reports as a 400 or 403, so such a key
// is confirmed with one GET /abilities instead, which every key may read.
// Only a 401 is revoked. A routing key is never sent anywhere: the only
// request that would test it creates an incident and pages the on-call.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	if tok.Kind == KindRoutingKey {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "verifying would page the on-call; treat as live"}
	}
	resp, err := p.get(ctx, mePath, tok.Value)
	if err != nil {
		return detect.Unknown(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var r struct {
			User struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				Role  string `json:"role"`
			} `json:"user"`
		}
		_ = json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &r)
		return detect.Verification{Status: detect.StatusActive, Detail: strings.TrimSpace(fmt.Sprintf("user %s %s, role %s", r.User.Name, r.User.Email, r.User.Role))}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	case http.StatusBadRequest, http.StatusForbidden:
		return p.abilities(ctx, tok.Value)
	case http.StatusTooManyRequests:
		return detect.Unknown("rate limited")
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, mePath))
}

// abilities confirms a key that has no user of its own.
func (p *Provider) abilities(ctx context.Context, key string) detect.Verification {
	resp, err := p.get(ctx, abilitiesPath, key)
	if err != nil {
		return detect.Unknown(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		return detect.Verification{Status: detect.StatusActive, Detail: "general access key (account-level)"}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	case http.StatusTooManyRequests:
		return detect.Unknown("rate limited")
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, abilitiesPath))
}

func (p *Provider) get(ctx context.Context, path, key string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token token="+key)
	req.Header.Set("Accept", accept)
	return detect.Do(p.Client, req)
}
