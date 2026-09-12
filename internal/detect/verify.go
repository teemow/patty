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
	// Detail describes what the token gives access to: user and scopes, or
	// the number of repositories an installation token reaches.
	Detail string `json:"detail,omitempty"`
	// ClientID is the OAuth client id of the application the token was
	// issued to, when GitHub reports one.
	ClientID string `json:"client_id,omitempty"`
	// App is the name of that application when patty knows the client id.
	App string `json:"app,omitempty"`
	// Expires is when the token stops working, for tokens that expire.
	Expires string `json:"expires,omitempty"`
}

// Issuer names the application a token was issued to: the known app name,
// else the raw client id, else "".
func (v Verification) Issuer() string {
	if v.App != "" {
		return v.App
	}
	if v.ClientID != "" {
		return "OAuth app " + v.ClientID
	}
	return ""
}

// knownApps maps OAuth client ids to the applications that own them, so a
// report can say "issued to GitHub CLI" and point at the right settings page.
var knownApps = map[string]string{
	"178c6fc778ccc68e1d6a": "GitHub CLI",
	"Iv1.b507a08c87ecfe98": "GitHub Copilot",
	"de0e3c7e9973e1c4dd77": "GitHub Desktop",
	"01ab8ac9400c4e429b23": "Visual Studio Code",
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
		v := Verification{Status: StatusActive, Detail: describe(body, resp.Header)}
		if id := strings.TrimSpace(resp.Header.Get("X-OAuth-Client-Id")); id != "" {
			v.ClientID = id
			v.App = knownApps[id]
		}
		if exp := strings.TrimSpace(resp.Header.Get("GitHub-Authentication-Token-Expiration")); exp != "" {
			v.Expires = expiryDay(exp)
		}
		return v
	case http.StatusUnauthorized:
		return Verification{Status: StatusRevoked}
	default:
		return Verification{Status: StatusUnknown, Detail: fmt.Sprintf("HTTP %d from %s", resp.StatusCode, path)}
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
