package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

const (
	whoamiPath = "/-/whoami"
	tokensPath = "/-/npm/v1/tokens"
)

// tokenRecord is one entry of the account's token list. The registry
// shows the first characters of each token, which is how the leaked value
// finds its own record.
type tokenRecord struct {
	Token      string   `json:"token"`
	Key        string   `json:"key"`
	CIDR       []string `json:"cidr_whitelist"`
	ReadOnly   bool     `json:"readonly"`
	Automation bool     `json:"automation"`
	Created    string   `json:"created"`
}

func (r tokenRecord) describe() string {
	kind := "publish"
	switch {
	case r.ReadOnly:
		kind = "read-only"
	case r.Automation:
		kind = "automation"
	}
	s := kind
	if t, err := time.Parse(time.RFC3339, r.Created); err == nil {
		s += ", created " + t.UTC().Format("2006-01-02")
	}
	if len(r.CIDR) > 0 {
		s += ", cidr " + strings.Join(r.CIDR, " ")
	}
	return s
}

// Verify implements detect.Provider with one GET /-/whoami on the token's
// registry, the public one unless the .npmrc line named another. A live
// token then looks itself up in the account's token list to say whether
// it can publish; a granular token may not list tokens, which changes
// nothing about it being live. Only a 401 is revoked.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	registry, v, ok := p.registry(ctx, tok)
	if !ok {
		return v
	}
	resp, err := p.do(ctx, http.MethodGet, registry+whoamiPath, tok.Value)
	if err != nil {
		return detect.Unknown(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var who struct {
			Username string `json:"username"`
		}
		_ = json.Unmarshal(detect.ReadBody(resp.Body, 4096), &who)
		detail := "user " + who.Username + " on " + detect.HostOf(registry)
		if rec, err := p.lookup(ctx, registry, tok.Value); err == nil {
			detail += ", " + rec.describe()
		}
		return detect.Verification{Status: detect.StatusActive, Detail: detail}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	case http.StatusTooManyRequests:
		return detect.Unknown("rate limited")
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, detect.HostOf(registry)))
}

// registry returns the registry a token is checked against: the public
// one, or the private one its .npmrc line named, which the server policy
// has to admit.
func (p *Provider) registry(ctx context.Context, tok detect.Token) (string, detect.Verification, bool) {
	registry := strings.TrimRight(decode(tok).Registry, "/")
	if registry == "" || registry == publicRegistry || registry == p.RegistryURL {
		return p.RegistryURL, detect.Verification{}, true
	}
	if v, ok := p.Policy.Admit(ctx, registry); !ok {
		return "", v, false
	}
	return registry, detect.Verification{}, true
}

// lookup finds the token's own record in the account's list, by the
// leading characters the registry shows for each.
func (p *Provider) lookup(ctx context.Context, registry, token string) (tokenRecord, error) {
	resp, err := p.do(ctx, http.MethodGet, registry+tokensPath+"?perPage=100", token)
	if err != nil {
		return tokenRecord{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return tokenRecord{}, fmt.Errorf("HTTP %d from %s", resp.StatusCode, tokensPath)
	}
	var list struct {
		Objects []tokenRecord `json:"objects"`
	}
	if err := json.Unmarshal(detect.ReadBody(resp.Body, 8<<20), &list); err != nil {
		return tokenRecord{}, err
	}
	for _, rec := range list.Objects {
		head := strings.TrimSuffix(rec.Token, "…")
		if head != "" && strings.HasPrefix(token, head) {
			return rec, nil
		}
	}
	return tokenRecord{}, fmt.Errorf("not in the account's token list")
}

func (p *Provider) do(ctx context.Context, method, target, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return detect.Do(p.Client, req)
}
