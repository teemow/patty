package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

// listLimit is the most keys the Admin API returns per page.
const listLimit = 1000

// apiKey is one entry of the organization's key list.
type apiKey struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// Hint is the partially redacted key Anthropic shows for it,
	// `sk-ant-api03-R2D…igAA`; it is how a leaked value is matched.
	Hint  string `json:"partial_key_hint"`
	Scope struct {
		Type        string `json:"type"`
		WorkspaceID string `json:"workspace_id"`
	} `json:"scope"`
	CreatedBy *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"created_by"`
}

// describe names the key the way the Console does: name, workspace, creator.
func (k apiKey) describe() string {
	parts := []string{"key " + k.Name}
	if k.Scope.WorkspaceID != "" {
		parts = append(parts, "workspace "+k.Scope.WorkspaceID)
	} else {
		parts = append(parts, "organization-wide")
	}
	if k.CreatedBy != nil {
		parts = append(parts, "created by "+strings.ReplaceAll(k.CreatedBy.Type, "_", " ")+" "+k.CreatedBy.ID)
	}
	return strings.Join(parts, ", ")
}

// Revoke implements detect.Revoker by setting each API key to inactive
// through the Admin API, which needs the operator's admin key: Anthropic
// has no endpoint for reporting a leaked key. The key is found in the
// organization's key list by the partial hint Anthropic shows for it; a key
// no hint matches belongs to another organization and is reported as such,
// not as revoked. An inactive key can be reactivated in the Console;
// archiving it for good is left to the owner.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	return detect.RevokeEach(ctx, tokens, func(ctx context.Context, tok detect.Token) error {
		return p.deactivate(ctx, tok, false)
	})
}

// DryRunRevoke implements detect.DryRunRevoker: it finds the key in the
// organization's list exactly as Revoke would, and stops there.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	return p.deactivate(ctx, tok, true)
}

func (p *Provider) deactivate(ctx context.Context, tok detect.Token, dryRun bool) error {
	switch tok.Kind {
	case KindAdminKey:
		return errors.New("admin keys cannot be deactivated through the API; do it at " + adminKeysPage)
	case KindOAuth, KindRefresh:
		return errors.New("OAuth tokens cannot be revoked through the API; " + logout)
	}
	if p.AdminKey == "" {
		return errors.New("no admin key configured: set " + AdminKeyEnv + " to an Admin API key of the organization, or deactivate the key at " + keysPage)
	}
	key, err := p.lookup(ctx, tok.Value)
	if err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	return p.setStatus(ctx, key, "inactive")
}

// lookup finds the one key in the organization whose hint fits value.
func (p *Provider) lookup(ctx context.Context, value string) (apiKey, error) {
	keys, err := p.inventory(ctx)
	if err != nil {
		return apiKey{}, err
	}
	var matches []apiKey
	for _, k := range keys {
		if detect.HintMatches(k.Hint, value) {
			matches = append(matches, k)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return apiKey{}, errors.New("not in this organization: no key hint matches it; it belongs to another organization, deactivate it at " + keysPage)
	default:
		return apiKey{}, fmt.Errorf("matches the hints of %d keys in this organization; deactivate it at %s", len(matches), keysPage)
	}
}

// inventory lists the organization's API keys once, with the admin key.
// Every status is listed: a key that was deactivated after the leak is
// still found and described.
func (p *Provider) inventory(ctx context.Context) ([]apiKey, error) {
	if p.AdminKey == "" {
		return nil, errors.New("no admin key configured")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keys != nil {
		return p.keys, nil
	}
	admin := detect.Token{Kind: KindAdminKey, Value: p.AdminKey}
	var keys []apiKey
	after := ""
	for {
		q := url.Values{"limit": {fmt.Sprint(listLimit)}}
		if after != "" {
			q.Set("after_id", after)
		}
		var page struct {
			Data    []apiKey `json:"data"`
			HasMore bool     `json:"has_more"`
			LastID  string   `json:"last_id"`
		}
		if err := p.admin(ctx, http.MethodGet, "/v1/organizations/api_keys?"+q.Encode(), admin, nil, &page); err != nil {
			return nil, err
		}
		keys = append(keys, page.Data...)
		if !page.HasMore || page.LastID == "" {
			break
		}
		after = page.LastID
	}
	if keys == nil {
		keys = []apiKey{}
	}
	p.keys = keys
	return keys, nil
}

func (p *Provider) setStatus(ctx context.Context, key apiKey, status string) error {
	body, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return err
	}
	var updated apiKey
	admin := detect.Token{Kind: KindAdminKey, Value: p.AdminKey}
	if err := p.admin(ctx, http.MethodPost, "/v1/organizations/api_keys/"+url.PathEscape(key.ID), admin, bytes.NewReader(body), &updated); err != nil {
		return err
	}
	if updated.Status != status {
		return fmt.Errorf("the key is still %s after Anthropic accepted the request", updated.Status)
	}
	return nil
}

// admin sends one Admin API request and decodes a 200 into out.
func (p *Provider) admin(ctx context.Context, method, path string, key detect.Token, body io.Reader, out any) error {
	resp, err := p.do(ctx, method, path, key, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw := detect.ReadBody(resp.Body, 8<<20)
	if resp.StatusCode != http.StatusOK {
		var e apiError
		_ = json.Unmarshal(raw, &e)
		if resp.StatusCode == http.StatusUnauthorized {
			return errors.New(AdminKeyEnv + " is not accepted by Anthropic: " + e.Error.Message)
		}
		return errors.New("Admin API: " + httpError(resp.StatusCode, path, e))
	}
	return json.Unmarshal(raw, out)
}
