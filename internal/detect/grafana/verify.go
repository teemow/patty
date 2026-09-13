package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

// userPath is the one endpoint --verify reads on an instance: it needs no
// permission beyond authenticating and names the identity the token runs
// as, a service account since Grafana 9.1.
const userPath = "/api/user"

// Verify implements detect.Provider. A service account token or API key is
// tried against every candidate instance: the ones the operator named,
// as given, then the ones the scanned repository named, subject to the
// server policy. The first instance that accepts it settles it; it is
// revoked only when every instance answers 401. A Cloud token is checked
// against grafana.com's token list in its region.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	if tok.Kind == KindCloudToken {
		return p.verifyCloud(ctx, tok)
	}
	instances := detect.Uniq(append(append([]string(nil), p.Configured...), bound(tok)...)...)
	if len(instances) == 0 {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "instance unknown: the token does not name its Grafana and the scanned content named none; pass " + URLFlag + " or set " + URLEnv}
	}
	operator := detect.Set(p.Configured)
	return detect.AcrossInstances(instances, func(instance string) detect.Verification {
		if !operator[instance] {
			if v, ok := p.Policy.Admit(ctx, instance); !ok {
				return v
			}
		}
		return p.checkInstance(ctx, instance, tok.Value)
	})
}

// checkInstance sends one GET /api/user to the instance with the token.
func (p *Provider) checkInstance(ctx context.Context, instance, token string) detect.Verification {
	resp, err := p.get(ctx, strings.TrimRight(instance, "/")+userPath, token)
	if err != nil {
		return detect.Unknown(detect.HostOf(instance) + " not reachable from here: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	host := detect.HostOf(instance)
	switch resp.StatusCode {
	case http.StatusOK:
		var u struct {
			Login          string `json:"login"`
			OrgID          int64  `json:"orgId"`
			IsGrafanaAdmin bool   `json:"isGrafanaAdmin"`
		}
		_ = json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &u)
		detail := "accepted by " + host + " as " + u.Login + ", org " + strconv.FormatInt(u.OrgID, 10)
		if u.IsGrafanaAdmin {
			detail += ", Grafana admin"
		}
		return detect.Verification{Status: detect.StatusActive, Detail: detail}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	case http.StatusForbidden:
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted by " + host + ", but not allowed to read " + userPath}
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, host))
}

// cloudItems is the envelope of the Grafana Cloud API's list endpoints.
type cloudItems[T any] struct {
	Items []T `json:"items"`
}

type cloudTokenRecord struct {
	ID             string `json:"id"`
	AccessPolicyID string `json:"accessPolicyId"`
	Name           string `json:"name"`
	ExpiresAt      string `json:"expiresAt"`
}

type cloudPolicy struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

// verifyCloud lists the org's tokens in the token's region with the token
// itself, which needs accesspolicies:read. A token without that scope
// answers 403 and is live all the same; only 401 is revoked.
func (p *Provider) verifyCloud(ctx context.Context, tok detect.Token) detect.Verification {
	ct, ok := DecodeCloud(strings.TrimPrefix(tok.Value, cloudPrefix))
	if !ok {
		return detect.Unknown("the token's JSON does not decode")
	}
	region := ""
	if ct.Meta.Region != "" {
		region = "?region=" + url.QueryEscape(ct.Meta.Region)
	}
	resp, err := p.get(ctx, p.CloudURL+"/api/v1/tokens"+region, tok.Value)
	if err != nil {
		return detect.Unknown(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var list cloudItems[cloudTokenRecord]
		_ = json.Unmarshal(detect.ReadBody(resp.Body, 8<<20), &list)
		return p.describeCloud(ctx, tok.Value, ct, list.Items, region)
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	case http.StatusForbidden:
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted by grafana.com for org " + ct.Org + ", but the token's scopes do not include accesspolicies:read"}
	case http.StatusTooManyRequests:
		return detect.Unknown("rate limited")
	}
	return detect.Unknown(fmt.Sprintf("HTTP %d from grafana.com", resp.StatusCode))
}

// describeCloud names the token's own record in the list and, when the
// policies can be read too, the access policy and scopes it carries.
func (p *Provider) describeCloud(ctx context.Context, token string, ct cloudToken, records []cloudTokenRecord, region string) detect.Verification {
	v := detect.Verification{Status: detect.StatusActive, Detail: "accepted by grafana.com for org " + ct.Org}
	var own *cloudTokenRecord
	for i := range records {
		if records[i].Name == ct.Name {
			own = &records[i]
			break
		}
	}
	if own == nil {
		v.Detail += ", token " + ct.Name + " not in the org's token list"
		return v
	}
	v.Detail += ", token " + own.Name
	if own.ExpiresAt != "" {
		v.Expires = own.ExpiresAt
		if len(v.Expires) > 10 {
			v.Expires = v.Expires[:10]
		}
	}
	if policy, ok := p.policy(ctx, token, own.AccessPolicyID, region); ok {
		v.Detail += ", access policy " + policy.Name
		if len(policy.Scopes) > 0 {
			v.Detail += ", scopes " + strings.Join(policy.Scopes, " ")
		}
	} else {
		v.Detail += ", access policy " + own.AccessPolicyID
	}
	return v
}

func (p *Provider) policy(ctx context.Context, token, id, region string) (cloudPolicy, bool) {
	resp, err := p.get(ctx, p.CloudURL+"/api/v1/accesspolicies/"+url.PathEscape(id)+region, token)
	if err != nil {
		return cloudPolicy{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	var policy cloudPolicy
	if resp.StatusCode != http.StatusOK || json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &policy) != nil || policy.Name == "" {
		return cloudPolicy{}, false
	}
	return policy, true
}

func (p *Provider) get(ctx context.Context, target, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return detect.Do(p.Client, req)
}
