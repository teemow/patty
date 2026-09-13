package gitlab

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	selfPath   = "/api/v4/personal_access_tokens/self"
	runnerPath = "/api/v4/runners/verify"
	jwtPath    = "/jwt/auth?service=container_registry"
)

// unverifiable says, per family, why --verify has nobody to ask.
var unverifiable = map[detect.Kind]string{
	KindJobToken:               "a job token is only valid while its job runs; nothing to ask afterwards",
	KindTriggerToken:           "the only request a trigger token answers starts a pipeline",
	KindFeedToken:              "a feed token is only accepted by the instance's RSS feeds, which the token does not name; reset it if in doubt",
	KindIncomingMailToken:      "an incoming mail token is only used in email addresses; reset it if in doubt",
	KindAgentToken:             "an agent token is only accepted by the agent server (KAS) of its instance, which the token does not name",
	KindOAuthAppSecret:         "an application secret needs its client id and a grant to do anything; renew it if in doubt",
	KindFeatureFlagClientToken: "a feature flag client token is only accepted together with its project's Unleash URL, which the token does not name",
	KindSCIMToken:              "a SCIM token is only accepted by its group's SCIM endpoint, which the token does not name; reset it if in doubt",
}

// Verify implements detect.Provider. A personal access token is tried
// against every candidate instance with GET /personal_access_tokens/self,
// a runner token with POST /runners/verify, a deploy token, together with
// its username, against the registry's token endpoint: gitlab.com and the
// instances the operator named, as given, then the ones the scanned
// repository named, subject to the server policy. The first instance that
// accepts it settles it; it is revoked only when every instance rejected
// it. Every other family has nobody to ask.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	if why, ok := unverifiable[tok.Kind]; ok {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: why}
	}
	c := decode(tok)
	if tok.Kind == KindDeployToken && c.Username == "" {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "found without its username (" + deployUserPrefix + "N): a deploy token is only accepted together with it"}
	}
	return p.across(ctx, c.Instances, func(instance string) detect.Verification {
		switch tok.Kind {
		case KindRunnerToken:
			return p.checkRunner(ctx, instance, tok.Value)
		case KindDeployToken:
			return p.checkDeploy(ctx, instance, c.Username, tok.Value)
		}
		return p.checkPAT(ctx, instance, tok.Value)
	})
}

// across tries check on every candidate instance: the default and the
// configured ones as the operator gave them, then the discovered ones the
// policy admits.
func (p *Provider) across(ctx context.Context, discovered []string, check func(instance string) detect.Verification) detect.Verification {
	operator := trimmed(append([]string{p.DefaultURL}, p.Configured...))
	given := detect.Set(operator)
	return detect.AcrossInstances(detect.Uniq(append(operator, trimmed(discovered)...)...), func(instance string) detect.Verification {
		if !given[instance] {
			if v, ok := p.Policy.Admit(ctx, instance); !ok {
				return v
			}
		}
		return check(instance)
	})
}

// patInfo is what GET /personal_access_tokens/self says about a token.
type patInfo struct {
	Name      string   `json:"name"`
	Revoked   bool     `json:"revoked"`
	Active    bool     `json:"active"`
	Scopes    []string `json:"scopes"`
	UserID    int64    `json:"user_id"`
	ExpiresAt string   `json:"expires_at"`
	LastUsed  string   `json:"last_used_at"`
}

func (p *Provider) checkPAT(ctx context.Context, instance, token string) detect.Verification {
	resp, err := p.do(ctx, http.MethodGet, instance+selfPath, token, "")
	if err != nil {
		return detect.Unknown(detect.HostOf(instance) + " not reachable from here: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	host := detect.HostOf(instance)
	switch resp.StatusCode {
	case http.StatusOK:
		var info patInfo
		_ = json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &info)
		switch {
		case info.Revoked:
			return detect.Verification{Status: detect.StatusRevoked, Detail: host + " lists it as revoked"}
		case !info.Active:
			return detect.Verification{Status: detect.StatusRevoked, Detail: host + " lists it as inactive"}
		}
		v := detect.Verification{Status: detect.StatusActive, Detail: fmt.Sprintf("accepted by %s: token %s, user id %d, scopes %s", host, info.Name, info.UserID, strings.Join(info.Scopes, " "))}
		if info.LastUsed != "" {
			v.Detail += ", last used " + day(info.LastUsed)
		}
		if info.ExpiresAt != "" {
			v.Expires = day(info.ExpiresAt)
		}
		return v
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	case http.StatusForbidden:
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted by " + host + ", but its scopes do not allow reading " + selfPath}
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, host))
}

// checkRunner posts the token to /runners/verify, which every runner does
// on start: 200 means the runner exists, 403 that the token is gone.
func (p *Provider) checkRunner(ctx context.Context, instance, token string) detect.Verification {
	resp, err := p.do(ctx, http.MethodPost, instance+runnerPath, "", "token="+token)
	if err != nil {
		return detect.Unknown(detect.HostOf(instance) + " not reachable from here: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	host := detect.HostOf(instance)
	switch resp.StatusCode {
	case http.StatusOK:
		var r struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(detect.ReadBody(resp.Body, 4096), &r)
		detail := "runner token accepted by " + host
		if r.ID != 0 {
			detail += fmt.Sprintf(", runner %d", r.ID)
		}
		return detect.Verification{Status: detect.StatusActive, Detail: detail}
	case http.StatusForbidden:
		return detect.Verification{Status: detect.StatusRevoked}
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, host))
}

// checkDeploy asks the instance's registry token endpoint for a token with
// the deploy login and no scope, which reads nothing.
func (p *Provider) checkDeploy(ctx context.Context, instance, username, token string) detect.Verification {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, instance+jwtPath, nil)
	if err != nil {
		return detect.Unknown(err.Error())
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+token)))
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return detect.Unknown(detect.HostOf(instance) + " not reachable from here: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	host := detect.HostOf(instance)
	switch resp.StatusCode {
	case http.StatusOK:
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted by " + host + " as " + username}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, host))
}

// do sends one request, with the token in PRIVATE-TOKEN when there is one
// and a form body when there is one.
func (p *Provider) do(ctx context.Context, method, target, token, form string) (*http.Response, error) {
	var body io.Reader
	if form != "" {
		body = strings.NewReader(form)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	if form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Accept", "application/json")
	return detect.Do(p.Client, req)
}

// day reduces GitLab's timestamps to a date.
func day(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

// trimmed returns the instances without trailing slashes, so the same
// instance spelled two ways is one candidate.
func trimmed(instances []string) []string {
	out := make([]string, 0, len(instances))
	for _, instance := range instances {
		out = append(out, strings.TrimRight(instance, "/"))
	}
	return out
}
