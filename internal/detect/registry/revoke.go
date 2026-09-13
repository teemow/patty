package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/teemow/patty/internal/detect"
)

const (
	// accessTokensPath lists and edits the personal access tokens of the
	// account a JWT belongs to.
	accessTokensPath = "/v2/access-tokens"
	// recentUse is how long ago a token's last use may be to count as the
	// login patty just did with it.
	recentUse = 5 * time.Minute
)

// accessToken is one entry of Docker Hub's personal access token list.
type accessToken struct {
	UUID     string   `json:"uuid"`
	Label    string   `json:"token_label"`
	Active   bool     `json:"is_active"`
	Scopes   []string `json:"scopes"`
	Token    string   `json:"token"`
	LastUsed string   `json:"last_used"`
}

// readOnly reports whether the token may only read, in which case Docker
// Hub does not let it manage tokens, itself included.
func (t accessToken) readOnly() bool {
	for _, s := range t.Scopes {
		if s != "repo:read" && s != "repo:public_read" {
			return false
		}
	}
	return true
}

// Revoke implements detect.Provider for Docker Hub personal access tokens,
// the only kind a registry lets patty revoke: the token logs in, obtains a
// JWT for its account, finds itself in the account's token list and sets
// itself inactive. A read-only token may not manage tokens and says so. A
// deactivated token can be reactivated by its owner; deleting it is left to
// them. Every other kind is rotated by hand as the report says.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	var errs []error
	for _, tok := range tokens {
		if err := p.deactivate(ctx, tok, false); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", detect.Redact(tok.Value), err))
		}
	}
	return errors.Join(errs...)
}

// DryRunRevoke implements detect.DryRunRevoker: it logs in and finds the
// token in the account's list exactly as Revoke would, and changes nothing.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	return p.deactivate(ctx, tok, true)
}

func (p *Provider) deactivate(ctx context.Context, tok detect.Token, dryRun bool) error {
	if tok.Kind != KindHubPAT {
		return errors.New("only Docker Hub personal access tokens can be revoked through the API; rotate this credential as the report says")
	}
	if tok.Secret == "" {
		return errors.New("username not found next to the token; deactivate it at " + hubSecurityPage)
	}
	jwt, status, err := p.hubJWT(ctx, tok.Secret, tok.Value)
	switch {
	case err != nil:
		return err
	case status == http.StatusUnauthorized:
		return errors.New("already rejected by Docker Hub")
	case status != http.StatusOK || jwt == "":
		return fmt.Errorf("HTTP %d from Docker Hub's login endpoint", status)
	}
	match, err := p.lookup(ctx, jwt, tok.Value)
	if err != nil {
		return err
	}
	if match.readOnly() {
		return fmt.Errorf("token %q is read-only and may not deactivate itself; deactivate it at %s", match.Label, hubSecurityPage)
	}
	if dryRun {
		return nil
	}
	return p.patch(ctx, jwt, match)
}

// lookup finds the leaked token in its account's token list. Docker Hub
// lists tokens without their value, so the match is made in the most
// reliable way the answers allow: the entry whose token field fits the
// value, then the token id the JWT names, then the only active token, then
// the only token used within the last minutes, which was the login just
// made. Anything less certain is left to the owner.
func (p *Provider) lookup(ctx context.Context, jwt, value string) (accessToken, error) {
	list, err := p.accessTokens(ctx, jwt)
	if err != nil {
		return accessToken{}, err
	}
	var active, recent []accessToken
	for _, t := range list {
		if t.Token != "" && (t.Token == value || detect.HintMatches(t.Token, value)) {
			return t, nil
		}
		if t.UUID != "" && t.UUID == jwtClaim(jwt, "token_id") {
			return t, nil
		}
		if t.Active {
			active = append(active, t)
			if used, err := time.Parse(time.RFC3339, t.LastUsed); err == nil && time.Since(used) < recentUse {
				recent = append(recent, t)
			}
		}
	}
	switch {
	case len(active) == 1:
		return active[0], nil
	case len(recent) == 1:
		return recent[0], nil
	case len(active) == 0:
		return accessToken{}, errors.New("the account lists no active personal access token, yet the login succeeded; deactivate it at " + hubSecurityPage)
	}
	return accessToken{}, fmt.Errorf("cannot tell which of the account's %d active tokens this is; deactivate it at %s", len(active), hubSecurityPage)
}

// accessTokens lists the account's personal access tokens with the JWT.
func (p *Provider) accessTokens(ctx context.Context, jwt string) ([]accessToken, error) {
	resp, err := p.get(ctx, p.HubURL+accessTokensPath+"?page_size=100", "Bearer "+jwt)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, errors.New("the token may not list the account's tokens (read-only tokens cannot); deactivate it at " + hubSecurityPage)
		}
		return nil, fmt.Errorf("HTTP %d listing the account's access tokens", resp.StatusCode)
	}
	var page struct {
		Results []accessToken `json:"results"`
	}
	if err := json.Unmarshal(detect.ReadBody(resp.Body, 8<<20), &page); err != nil {
		return nil, err
	}
	return page.Results, nil
}

// patch sets the token inactive.
func (p *Provider) patch(ctx context.Context, jwt string, t accessToken) error {
	body, err := json.Marshal(map[string]bool{"is_active": false})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, p.HubURL+accessTokensPath+"/"+t.UUID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("token %q may not deactivate itself; deactivate it at %s", t.Label, hubSecurityPage)
	}
	return fmt.Errorf("HTTP %d deactivating token %q", resp.StatusCode, t.Label)
}
