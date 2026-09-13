package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

// apiError is a non-200 answer of the API, with what OpenAI said about it.
type apiError struct {
	status int
	path   string
	body   struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
}

func (e *apiError) Error() string {
	s := fmt.Sprintf("HTTP %d from %s", e.status, e.path)
	if e.body.Error.Message != "" {
		s += ": " + e.body.Error.Message
	}
	return s
}

// Verify implements detect.Provider with one request: listing models, which
// every key may do, or listing the organization's admin keys for an admin
// key, which is the only thing such a key is for and also names it. Only
// OpenAI's invalid_api_key answer counts as revoked. A 429 is reported as
// unknown, because a key whose quota is exhausted answers 429 just like a
// rate-limited one and is still very much live.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	if tok.Kind == KindAdmin {
		keys, err := p.list(ctx, tok.Value, "/v1/organization/admin_api_keys", adminEntry)
		if err != nil {
			return verdict(err)
		}
		detail := "admin key, accepted by the API"
		if e, err := match(keys, tok.Value); err == nil {
			detail = e.label
		}
		return detect.Verification{Status: detect.StatusActive, Detail: detail}
	}
	_, header, err := p.get(ctx, tok.Value, "/v1/models")
	if err != nil {
		return verdict(err)
	}
	var parts []string
	if org := strings.TrimSpace(header.Get("openai-organization")); org != "" {
		parts = append(parts, "organization "+org)
	}
	if project := strings.TrimSpace(header.Get("openai-project")); project != "" {
		parts = append(parts, "project "+project)
	}
	if len(parts) == 0 {
		parts = append(parts, "accepted by the API")
	}
	if tok.Kind != KindLegacy {
		if e, err := p.lookup(ctx, tok); err == nil {
			parts = append(parts, e.label)
		}
	}
	return detect.Verification{Status: detect.StatusActive, Detail: strings.Join(parts, ", ")}
}

// verdict turns a failed request into a verification.
func verdict(err error) detect.Verification {
	var e *apiError
	if !errors.As(err, &e) {
		return detect.Verification{Status: detect.StatusUnknown, Detail: err.Error()}
	}
	switch {
	case e.status == http.StatusUnauthorized && e.body.Error.Code == "invalid_api_key":
		return detect.Verification{Status: detect.StatusRevoked}
	case e.status == http.StatusTooManyRequests:
		return detect.Verification{Status: detect.StatusUnknown, Detail: "rate limited, or the key's quota is exhausted; OpenAI answers both alike, so the key may well be live"}
	default:
		return detect.Verification{Status: detect.StatusUnknown, Detail: e.Error()}
	}
}

// get sends one authenticated GET and returns the body and headers of a
// 200; anything else is an *apiError.
func (p *Provider) get(ctx context.Context, key, path string) ([]byte, http.Header, error) {
	return p.do(ctx, http.MethodGet, key, path, nil)
}

func (p *Provider) do(ctx context.Context, method, key, path string, body io.Reader) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw := detect.ReadBody(resp.Body, 8<<20)
	if resp.StatusCode != http.StatusOK {
		e := &apiError{status: resp.StatusCode, path: strings.SplitN(path, "?", 2)[0]}
		_ = json.Unmarshal(raw, &e.body)
		return nil, nil, e
	}
	return raw, resp.Header, nil
}
