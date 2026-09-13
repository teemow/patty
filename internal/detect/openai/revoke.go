package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

// listLimit is the most objects the Admin API returns per page.
const listLimit = 100

// entry is one key of the organization as the Admin API lists it: the
// redacted value it is matched by, where it is deleted, and how the report
// names it.
type entry struct {
	hint  string
	path  string
	label string
}

// page is the envelope of every Admin API list.
type page struct {
	Data    []json.RawMessage `json:"data"`
	HasMore bool              `json:"has_more"`
	LastID  string            `json:"last_id"`
}

// adminKey is one entry of the organization's admin key list.
type adminKey struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Hint  string `json:"redacted_value"`
	Owner struct {
		Name string `json:"name"`
	} `json:"owner"`
}

func adminEntry(raw json.RawMessage) (entry, error) {
	var k adminKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return entry{}, err
	}
	label := "admin key " + k.Name
	if k.Owner.Name != "" {
		label += ", owned by " + k.Owner.Name
	}
	return entry{hint: k.Hint, path: "/v1/organization/admin_api_keys/" + url.PathEscape(k.ID), label: label}, nil
}

// project is one entry of the organization's project list.
type project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// projectKey is one entry of a project's key list.
type projectKey struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Hint  string `json:"redacted_value"`
	Owner struct {
		Type string `json:"type"`
		User struct {
			Name string `json:"name"`
		} `json:"user"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"service_account"`
	} `json:"owner"`
}

func projectEntry(proj project) func(json.RawMessage) (entry, error) {
	return func(raw json.RawMessage) (entry, error) {
		var k projectKey
		if err := json.Unmarshal(raw, &k); err != nil {
			return entry{}, err
		}
		label := "key " + k.Name + " in project " + proj.Name
		switch k.Owner.Type {
		case "user":
			label += ", owned by " + k.Owner.User.Name
		case "service_account":
			label += ", owned by service account " + k.Owner.ServiceAccount.Name
		}
		return entry{hint: k.Hint, path: "/v1/organization/projects/" + url.PathEscape(proj.ID) + "/api_keys/" + url.PathEscape(k.ID), label: label}, nil
	}
}

// Revoke implements detect.Provider by deleting each key through the Admin
// API, which needs the operator's admin key: OpenAI has no endpoint for
// reporting a leaked key. Admin keys are found in the organization's admin
// key list, project and service account keys in the key lists of every
// project, by the redacted value OpenAI shows for each key. A key no entry
// matches belongs to another organization and is reported as such, not as
// revoked. Deletion is final.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	return detect.RevokeEach(ctx, tokens, func(ctx context.Context, tok detect.Token) error {
		return p.remove(ctx, tok, false)
	})
}

// DryRunRevoke implements detect.DryRunRevoker: it finds the key in the
// organization exactly as Revoke would, and stops there.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	return p.remove(ctx, tok, true)
}

func (p *Provider) remove(ctx context.Context, tok detect.Token, dryRun bool) error {
	if tok.Kind == KindLegacy {
		return errors.New("legacy user keys are not listed by the Admin API; revoke it at " + keysPage)
	}
	if p.AdminKey == "" {
		return errors.New("no admin key configured: set " + AdminKeyEnv + " to an admin key of the organization, or revoke the key at " + keysPage)
	}
	e, err := p.lookup(ctx, tok)
	if err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	var deleted struct {
		Deleted bool `json:"deleted"`
	}
	raw, _, err := p.do(ctx, http.MethodDelete, p.AdminKey, e.path, nil)
	if err != nil {
		return adminError(err)
	}
	if json.Unmarshal(raw, &deleted) != nil || !deleted.Deleted {
		return errors.New("OpenAI accepted the request but did not report the key as deleted")
	}
	return nil
}

// lookup finds the one key in the organization whose redacted value fits
// the token, in the list of its family.
func (p *Provider) lookup(ctx context.Context, tok detect.Token) (entry, error) {
	if p.AdminKey == "" {
		return entry{}, errors.New("no admin key configured")
	}
	entries, err := p.inventory(ctx, tok.Kind)
	if err != nil {
		return entry{}, err
	}
	return match(entries, tok.Value)
}

func match(entries []entry, value string) (entry, error) {
	var matches []entry
	for _, e := range entries {
		if detect.HintMatches(e.hint, value) {
			matches = append(matches, e)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return entry{}, errors.New("not in this organization: no redacted key matches it; it belongs to another organization, revoke it at " + keysPage)
	default:
		return entry{}, fmt.Errorf("matches %d redacted keys in this organization; revoke it at %s", len(matches), keysPage)
	}
}

// inventory lists the organization's keys of the token's family once, with
// the admin key: the admin key list for admin keys, every project's key list
// for the rest.
func (p *Provider) inventory(ctx context.Context, kind detect.Kind) ([]entry, error) {
	family := KindProject
	if kind == KindAdmin {
		family = KindAdmin
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if entries, ok := p.entries[family]; ok {
		return entries, nil
	}
	entries, err := p.fetch(ctx, family)
	if err != nil {
		return nil, adminError(err)
	}
	if p.entries == nil {
		p.entries = map[detect.Kind][]entry{}
	}
	p.entries[family] = entries
	return entries, nil
}

func (p *Provider) fetch(ctx context.Context, family detect.Kind) ([]entry, error) {
	if family == KindAdmin {
		return p.list(ctx, p.AdminKey, "/v1/organization/admin_api_keys", adminEntry)
	}
	projects, err := listOf(ctx, p, p.AdminKey, "/v1/organization/projects?include_archived=true", func(raw json.RawMessage) (project, error) {
		var proj project
		return proj, json.Unmarshal(raw, &proj)
	})
	if err != nil {
		return nil, err
	}
	entries := []entry{}
	for _, proj := range projects {
		keys, err := p.list(ctx, p.AdminKey, "/v1/organization/projects/"+url.PathEscape(proj.ID)+"/api_keys?owner_project_access=any", projectEntry(proj))
		if err != nil {
			return nil, err
		}
		entries = append(entries, keys...)
	}
	return entries, nil
}

// list pages through one Admin API collection with the given key, decoding
// each object with decode.
func (p *Provider) list(ctx context.Context, key, path string, decode func(json.RawMessage) (entry, error)) ([]entry, error) {
	return listOf(ctx, p, key, path, decode)
}

func listOf[T any](ctx context.Context, p *Provider, key, path string, decode func(json.RawMessage) (T, error)) ([]T, error) {
	out := []T{}
	after := ""
	for {
		q := fmt.Sprintf("limit=%d", listLimit)
		if after != "" {
			q += "&after=" + url.QueryEscape(after)
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		raw, _, err := p.get(ctx, key, path+sep+q)
		if err != nil {
			return nil, err
		}
		var pg page
		if err := json.Unmarshal(raw, &pg); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, item := range pg.Data {
			v, err := decode(item)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			out = append(out, v)
		}
		if !pg.HasMore || pg.LastID == "" {
			return out, nil
		}
		after = pg.LastID
	}
}

// adminError says whose key failed when a request made with the operator's
// admin key is refused.
func adminError(err error) error {
	var e *apiError
	if errors.As(err, &e) && e.status == http.StatusUnauthorized {
		return errors.New(AdminKeyEnv + " is not accepted by OpenAI: " + e.body.Error.Message)
	}
	return fmt.Errorf("admin API: %w", err)
}
