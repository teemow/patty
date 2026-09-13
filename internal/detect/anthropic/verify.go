package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	apiVersion = "2023-06-01"
	// oauthBeta is the beta the API requires for OAuth bearer tokens;
	// without it every such token is rejected as unsupported.
	oauthBeta = "oauth-2025-04-20"
)

// apiError is the body of every non-200 answer.
type apiError struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Verify implements detect.Provider with one request that needs no
// permission beyond authenticating: listing models for API keys and OAuth
// access tokens, reading the organization for admin keys. Only Anthropic's
// authentication_error counts as revoked; a key that authenticates but may
// not do even that is live and reported as such.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	switch tok.Kind {
	case KindRefresh:
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "refresh tokens are exchanged through the OAuth client for a new access token, not usable against the API"}
	case KindAdminKey:
		return p.check(ctx, tok, "/v1/organizations/me", "read the organization", func(body []byte) string {
			var org struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(body, &org)
			return "admin key for organization " + org.Name
		})
	default:
		return p.check(ctx, tok, "/v1/models", "list models", func([]byte) string {
			detail := "accepted by the API"
			if tok.Kind == KindAPIKey {
				if key, err := p.lookup(ctx, tok.Value); err == nil {
					detail += ", " + key.describe()
				}
			}
			return detail
		})
	}
}

func (p *Provider) check(ctx context.Context, tok detect.Token, path, action string, describe func([]byte) string) detect.Verification {
	resp, err := p.do(ctx, http.MethodGet, path, tok, nil)
	if err != nil {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	body := detect.ReadBody(resp.Body, 1<<20)
	var e apiError
	_ = json.Unmarshal(body, &e)
	switch {
	case resp.StatusCode == http.StatusOK:
		return detect.Verification{Status: detect.StatusActive, Detail: describe(body)}
	case resp.StatusCode == http.StatusUnauthorized && e.Error.Type == "authentication_error" && !strings.Contains(e.Error.Message, "not supported"):
		return detect.Verification{Status: detect.StatusRevoked}
	case resp.StatusCode == http.StatusForbidden && e.Error.Type == "permission_error":
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted, but not allowed to " + action}
	case resp.StatusCode == http.StatusTooManyRequests:
		return detect.Verification{Status: detect.StatusUnknown, Detail: "rate limited"}
	default:
		return detect.Verification{Status: detect.StatusUnknown, Detail: httpError(resp.StatusCode, path, e)}
	}
}

// do sends one request authenticated with the token: OAuth tokens as bearer
// credentials under their beta, keys in x-api-key.
func (p *Provider) do(ctx context.Context, method, path string, tok detect.Token, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("anthropic-version", apiVersion)
	if tok.Kind == KindOAuth {
		req.Header.Set("Authorization", "Bearer "+tok.Value)
		req.Header.Set("anthropic-beta", oauthBeta)
	} else {
		req.Header.Set("x-api-key", tok.Value)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return detect.Do(p.Client, req)
}

// httpError renders a failed answer with what Anthropic said, when it said
// anything.
func httpError(status int, path string, e apiError) string {
	s := fmt.Sprintf("HTTP %d from %s", status, path)
	if e.Error.Message != "" {
		s += ": " + e.Error.Message
	}
	return s
}
