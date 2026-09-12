package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// knownApps maps OAuth client ids to the applications that own them, so a
// report can say "issued to GitHub CLI" and point at the right settings page.
var knownApps = map[string]string{
	"178c6fc778ccc68e1d6a": "GitHub CLI",
	"Iv1.b507a08c87ecfe98": "GitHub Copilot",
	"de0e3c7e9973e1c4dd77": "GitHub Desktop",
	"01ab8ac9400c4e429b23": "Visual Studio Code",
}

// Verify implements detect.Provider with one authenticated request. A 401
// is the only response treated as proof of revocation; anything but a clean
// 200 or 401 is reported as unknown.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	switch tok.Kind {
	case KindRefresh:
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "refresh tokens are exchanged through the OAuth app, not usable against the API"}
	case KindServerToServer:
		return p.check(ctx, tok.Value, "/installation/repositories", func(body []byte, h http.Header) string {
			var r struct {
				Total int `json:"total_count"`
			}
			_ = json.Unmarshal(body, &r)
			return fmt.Sprintf("installation token with access to %d repositories", r.Total)
		})
	default:
		return p.check(ctx, tok.Value, "/user", func(body []byte, h http.Header) string {
			var u struct {
				Login string `json:"login"`
			}
			_ = json.Unmarshal(body, &u)
			detail := "user " + u.Login
			if scopes := strings.TrimSpace(h.Get("X-OAuth-Scopes")); scopes != "" {
				detail += ", scopes: " + scopes
			}
			return detail
		})
	}
}

func (p *Provider) check(ctx context.Context, token, path string, describe func([]byte, http.Header) string) detect.Verification {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.BaseURL+path, nil)
	if err != nil {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		v := detect.Verification{Status: detect.StatusActive, Detail: describe(detect.ReadBody(resp.Body, 1<<20), resp.Header)}
		if id := strings.TrimSpace(resp.Header.Get("X-OAuth-Client-Id")); id != "" {
			v.ClientID = id
			v.App = knownApps[id]
		}
		if exp := strings.TrimSpace(resp.Header.Get("GitHub-Authentication-Token-Expiration")); exp != "" {
			v.Expires = expiryDay(exp)
		}
		return v
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	default:
		return detect.Verification{Status: detect.StatusUnknown, Detail: fmt.Sprintf("HTTP %d from %s", resp.StatusCode, path)}
	}
}

// expiryDay reduces GitHub's token expiration header ("2026-10-01 12:00:00
// UTC" or RFC 3339) to a date; the hour does not change what to do.
func expiryDay(s string) string {
	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02")
		}
	}
	return s
}
