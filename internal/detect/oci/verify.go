package oci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/jwt"
)

// hubLoginPath is Docker Hub's login endpoint, which accepts a password or
// a personal access token and answers with a JWT.
const hubLoginPath = "/v2/users/login"

// Verify implements detect.Provider with one exchange per credential and
// without pulling anything: a login makes one anonymous probe of the
// registry's /v2/ endpoint to learn where it hands out tokens, then one
// token request with the login and no scope. Docker Hub logins and tokens
// go to hub.docker.com's login endpoint instead, Quay OAuth tokens to the
// Quay API. A 401 is revoked; a 403 is a live credential that may not do
// what was asked, unless the registry answers a request without any
// credentials with 403 as well, as ghcr.io does: then the login was not
// accepted either.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	switch tok.Kind {
	case KindHubPAT, KindHubOAT:
		if tok.Secret == "" {
			return detect.Verification{Status: detect.StatusUnverifiable, Detail: "Docker Hub tokens only work with their username, and none was found nearby"}
		}
		return p.hubLogin(ctx, tok.Secret, tok.Value)
	case KindQuayRobot:
		return p.login(ctx, p.QuayHost, tok.Secret, tok.Value)
	case KindQuayOAuth:
		return p.quayOAuth(ctx, tok.Value)
	}
	host, user, _ := strings.Cut(tok.Value, "/")
	if tok.Secret == "" {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "password not found"}
	}
	if detect.Templated(host) {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "the registry is filled in at deploy time (" + host + "), nobody to ask"}
	}
	if isHub(host) {
		return p.hubLogin(ctx, user, tok.Secret)
	}
	return p.login(ctx, host, user, tok.Secret)
}

// login checks a username and password against a registry with the token
// dance every OCI registry speaks: GET /v2/ without credentials, which
// answers 401 with a WWW-Authenticate challenge naming the token realm and
// service, then GET realm?service=… with the login as HTTP Basic. A
// registry that challenges with Basic instead gets the login at /v2/
// itself. No scope is requested, so nothing about repositories is learned
// or touched.
func (p *Provider) login(ctx context.Context, host, user, password string) detect.Verification {
	where := host + ", user " + user
	probe, err := p.get(ctx, p.Scheme+"://"+host+"/v2/", "")
	if err != nil {
		return unknown(err.Error())
	}
	_ = probe.Body.Close()
	var target string
	switch probe.StatusCode {
	case http.StatusOK:
		return unknown(host + " answers /v2/ without credentials, so the login cannot be checked against it")
	case http.StatusUnauthorized:
		scheme, params := parseChallenge(probe.Header.Get("WWW-Authenticate"))
		switch {
		case strings.EqualFold(scheme, "bearer") && params["realm"] != "":
			target = params["realm"]
			if service := params["service"]; service != "" {
				target += "?service=" + url.QueryEscape(service)
			}
		case strings.EqualFold(scheme, "basic"):
			target = p.Scheme + "://" + host + "/v2/"
		default:
			return unknown(fmt.Sprintf("%s challenges with %q, which patty does not speak", host, probe.Header.Get("WWW-Authenticate")))
		}
	default:
		return unknown(fmt.Sprintf("HTTP %d from %s/v2/", probe.StatusCode, host))
	}
	resp, err := p.get(ctx, target, "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	if err != nil {
		return unknown(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		if strings.Contains(target, "/v2/") {
			return detect.Verification{Status: detect.StatusActive, Detail: where}
		}
		var t struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &t) != nil || (t.Token == "" && t.AccessToken == "") {
			return unknown("the token endpoint accepted the login but returned no token")
		}
		return detect.Verification{Status: detect.StatusActive, Detail: where}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	case http.StatusForbidden:
		return p.forbidden(ctx, target, host, where)
	default:
		return unknown(fmt.Sprintf("HTTP %d from the token endpoint of %s", resp.StatusCode, host))
	}
}

// forbidden settles a 403 from the token endpoint with one more request,
// without credentials. A registry that knows the login but will not hand
// it a token answers the login 403 and no credentials 401: the login is
// live. ghcr.io answers 403 to a wrong password and to no password alike,
// so a login that gets the same answer as no credentials was rejected.
func (p *Provider) forbidden(ctx context.Context, target, host, where string) detect.Verification {
	anon, err := p.get(ctx, target, "")
	if err != nil {
		return unknown(err.Error())
	}
	_ = anon.Body.Close()
	if anon.StatusCode == http.StatusForbidden {
		return detect.Verification{Status: detect.StatusRevoked, Detail: host + " rejects it (HTTP 403, the same answer a request without credentials gets)"}
	}
	return detect.Verification{Status: detect.StatusActive, Detail: where + ", accepted but forbidden to request a token (HTTP 403)"}
}

// hubLogin checks a Docker Hub username with a password or token against
// hub.docker.com, which answers a valid login with a JWT that names the
// account. A token or password can be checked in no other way.
func (p *Provider) hubLogin(ctx context.Context, user, password string) detect.Verification {
	token, status, err := p.hubJWT(ctx, user, password)
	switch {
	case err != nil:
		return unknown(err.Error())
	case status == http.StatusOK:
		account := user
		if name := jwtClaim(token, "username"); name != "" {
			account = name
		}
		return detect.Verification{Status: detect.StatusActive, Detail: "Docker Hub account " + account}
	case status == http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	}
	return unknown(fmt.Sprintf("HTTP %d from Docker Hub's login endpoint", status))
}

// hubJWT posts the login to Docker Hub and returns the JWT, if any, and
// the response status.
func (p *Provider) hubJWT(ctx context.Context, user, password string) (jwt string, status int, err error) {
	body, err := json.Marshal(map[string]string{"username": user, "password": password})
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.HubURL+hubLoginPath, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &r)
	return r.Token, resp.StatusCode, nil
}

// quayOAuth checks an OAuth token against the Quay API's user endpoint.
func (p *Provider) quayOAuth(ctx context.Context, token string) detect.Verification {
	resp, err := p.get(ctx, p.Scheme+"://"+p.QuayHost+quayAPIUser, "Bearer "+token)
	if err != nil {
		return unknown(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		var u struct {
			Username string `json:"username"`
		}
		_ = json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &u)
		return detect.Verification{Status: detect.StatusActive, Detail: p.QuayHost + ", user " + u.Username}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked}
	}
	return unknown(fmt.Sprintf("HTTP %d from the Quay API", resp.StatusCode))
}

// get sends one GET with the given Authorization header, if any.
func (p *Provider) get(ctx context.Context, target, authorization string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Accept", "application/json")
	return detect.Do(p.Client, req)
}

func unknown(detail string) detect.Verification {
	return detect.Verification{Status: detect.StatusUnknown, Detail: detail}
}

// parseChallenge splits a WWW-Authenticate header into its scheme and
// parameters: `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`.
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		var value string
		if strings.HasPrefix(after, `"`) {
			end := strings.IndexByte(after[1:], '"')
			if end < 0 {
				break
			}
			value, rest = after[1:end+1], after[end+2:]
		} else {
			value, rest, _ = strings.Cut(after, ",")
		}
		params[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return scheme, params
}

// jwtClaim reads one string claim from a JWT Docker Hub just issued to us
// over TLS, without verifying it: the claim only labels the report.
func jwtClaim(token, claim string) string {
	c, ok := jwt.Decode(token)
	if !ok {
		return ""
	}
	return c.String(claim)
}
