package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VerifyStatus is the outcome of checking a token against the GitHub API.
type VerifyStatus string

const (
	// StatusActive means the API accepted the token: it is live and must be revoked.
	StatusActive VerifyStatus = "active"
	// StatusRevoked means the API rejected the token as bad credentials.
	StatusRevoked VerifyStatus = "revoked"
	// StatusUnverifiable means the token family cannot be checked against the API.
	StatusUnverifiable VerifyStatus = "unverifiable"
	// StatusUnknown means the check could not be completed (network, rate limit).
	StatusUnknown VerifyStatus = "unknown"
)

// Verification is the result of Verifier.Verify.
type Verification struct {
	Status VerifyStatus `json:"status"`
	Detail string       `json:"detail,omitempty"`
}

// Verifier checks whether a token is still accepted by GitHub. It never
// stores or logs the token value.
type Verifier struct {
	// BaseURL is the API root, https://api.github.com by default.
	BaseURL string
	Client  *http.Client
}

// NewVerifier returns a Verifier against the public GitHub API.
func NewVerifier() *Verifier {
	return &Verifier{BaseURL: "https://api.github.com", Client: &http.Client{Timeout: 15 * time.Second}}
}

// Verify performs one authenticated request with the token and classifies
// the response. A 401 is the only response treated as proof of revocation;
// anything but a clean 200 or 401 is reported as unknown.
func (v *Verifier) Verify(ctx context.Context, tok Token) Verification {
	switch tok.Kind {
	case KindRefresh:
		return Verification{Status: StatusUnverifiable, Detail: "refresh tokens are exchanged through the OAuth app, not usable against the API"}
	case KindServerToServer:
		return v.check(ctx, tok.Value, "/installation/repositories", func(body []byte, h http.Header) string {
			var r struct {
				Total int `json:"total_count"`
			}
			_ = json.Unmarshal(body, &r)
			return fmt.Sprintf("installation token with access to %d repositories", r.Total)
		})
	default:
		return v.check(ctx, tok.Value, "/user", func(body []byte, h http.Header) string {
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

func (v *Verifier) check(ctx context.Context, token, path string, describe func([]byte, http.Header) string) Verification {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.BaseURL+path, nil)
	if err != nil {
		return Verification{Status: StatusUnknown, Detail: err.Error()}
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "patty")

	resp, err := v.Client.Do(req)
	if err != nil {
		return Verification{Status: StatusUnknown, Detail: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		body := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for len(body) < 1<<20 {
			n, rerr := resp.Body.Read(buf)
			body = append(body, buf[:n]...)
			if rerr != nil {
				break
			}
		}
		return Verification{Status: StatusActive, Detail: describe(body, resp.Header)}
	case http.StatusUnauthorized:
		return Verification{Status: StatusRevoked}
	default:
		return Verification{Status: StatusUnknown, Detail: fmt.Sprintf("HTTP %d from %s", resp.StatusCode, path)}
	}
}
