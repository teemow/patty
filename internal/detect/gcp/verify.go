package gcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
)

const (
	// cloudPlatformScope is the scope the assertion of a service account
	// key asks for; the token endpoint answers the same for any scope the
	// account may hold, and the access token it mints is discarded.
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	jwtBearerGrant     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// assertionLifetime is how long the signed assertion is valid; one
	// request needs a minute.
	assertionLifetime = time.Minute
	// googleHost is the domain a service account key's token_uri has to be
	// under to be honoured; a repository must not be able to send an
	// assertion, or anything else, to a server of its choosing.
	googleHost = "googleapis.com"
)

// oauthError is the body of every rejected token-endpoint request.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// Verify implements detect.Provider with one request per credential: a
// signed assertion to the token endpoint for a service account key, one
// tokeninfo call for an access token, one refresh for a refresh token
// that came with its OAuth client, one discovery call for an API key.
// Only Google's explicit invalid-credential answers count as revoked.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	switch tok.Kind {
	case KindServiceAccountKey:
		return p.verifyServiceAccount(ctx, tok)
	case KindAccessToken:
		return p.verifyAccessToken(ctx, tok)
	case KindUserCredentials, KindRefreshToken:
		return p.verifyRefreshToken(ctx, tok)
	case KindAPIKey:
		return p.verifyAPIKey(ctx, tok)
	}
	return unknown("no check for " + string(tok.Kind))
}

// verifyServiceAccount signs a one-minute assertion with the private key
// and asks the token endpoint for an access token, which is not kept. The
// endpoint tells a deleted key (the signature is no longer known), a
// deleted account and a disabled one apart.
func (p *Provider) verifyServiceAccount(ctx context.Context, tok detect.Token) detect.Verification {
	cred := decodeCredential(tok)
	key, err := parsePrivateKey(cred.PrivateKey)
	if err != nil {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "malformed key: " + err.Error()}
	}
	email, _, _ := strings.Cut(tok.Value, "/")
	endpoint := p.tokenURL(cred.TokenURI)
	assertion, err := p.assertion(key, email, endpoint)
	if err != nil {
		return unknown(err.Error())
	}
	status, body, err := p.post(ctx, endpoint, url.Values{"grant_type": {jwtBearerGrant}, "assertion": {assertion}})
	if err != nil {
		return unknown(err.Error())
	}
	who := "service account " + email
	if cred.Project != "" {
		who += " in " + cred.Project
	}
	if status == http.StatusOK {
		return detect.Verification{Status: detect.StatusActive, Detail: who}
	}
	var e oauthError
	_ = json.Unmarshal(body, &e)
	if status == http.StatusBadRequest && e.Error == "invalid_grant" {
		desc := strings.ToLower(e.Description)
		switch {
		case strings.Contains(desc, "invalid jwt signature"):
			return detect.Verification{Status: detect.StatusRevoked, Detail: "key deleted: the signature is no longer known to " + who}
		case strings.Contains(desc, "account not found"), strings.Contains(desc, "not a valid email"):
			return detect.Verification{Status: detect.StatusRevoked, Detail: who + " no longer exists"}
		case strings.Contains(desc, "disabled"):
			return detect.Verification{Status: detect.StatusRevoked, Detail: who + " is disabled: " + e.Description}
		}
	}
	return unknown(httpError(status, e))
}

// tokenURL is the endpoint the assertion goes to: the key's own token_uri
// when it is an https URL under googleapis.com, else the default.
func (p *Provider) tokenURL(own string) string {
	if u, err := url.Parse(own); err == nil && u.Scheme == "https" && (u.Hostname() == googleHost || strings.HasSuffix(u.Hostname(), "."+googleHost)) {
		return own
	}
	return p.TokenURL
}

// parsePrivateKey reads the RSA key of a service account, PKCS #8 as
// Google issues it, or PKCS #1.
func parsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("private_key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private_key is a %T, not an RSA key", parsed)
	}
	return key, nil
}

// assertion builds the RS256-signed JWT the token endpoint exchanges for
// an access token: issued by the account, for the cloud-platform scope,
// valid for one minute.
func (p *Provider) assertion(key *rsa.PrivateKey, email, audience string) (string, error) {
	now := p.now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   email,
		"scope": cloudPlatformScope,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(assertionLifetime).Unix(),
	})
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// tokenInfo is what the tokeninfo endpoint says about an access token.
type tokenInfo struct {
	Email     string `json:"email"`
	Scope     string `json:"scope"`
	Audience  string `json:"aud"`
	Party     string `json:"azp"`
	ExpiresIn string `json:"expires_in"`
}

// verifyAccessToken asks tokeninfo, which needs nothing but the token and
// says whose it is, what it may do and how long it lasts.
func (p *Provider) verifyAccessToken(ctx context.Context, tok detect.Token) detect.Verification {
	status, body, err := p.post(ctx, p.TokenInfoURL, url.Values{"access_token": {tok.Value}})
	if err != nil {
		return unknown(err.Error())
	}
	var e oauthError
	_ = json.Unmarshal(body, &e)
	switch {
	case status == http.StatusOK:
		var info tokenInfo
		_ = json.Unmarshal(body, &info)
		v := detect.Verification{Status: detect.StatusActive, Detail: describeToken(info), ClientID: info.Party}
		if v.ClientID == "" {
			v.ClientID = info.Audience
		}
		if secs, err := strconv.Atoi(info.ExpiresIn); err == nil {
			v.Expires = p.now().Add(time.Duration(secs) * time.Second).UTC().Format("2006-01-02 15:04 UTC")
		}
		return v
	case status == http.StatusBadRequest && e.Error == "invalid_token":
		return detect.Verification{Status: detect.StatusRevoked, Detail: "expired or revoked"}
	}
	return unknown(httpError(status, e))
}

func describeToken(info tokenInfo) string {
	var parts []string
	if info.Email != "" {
		parts = append(parts, "account "+info.Email)
	}
	if info.Scope != "" {
		parts = append(parts, "scopes: "+strings.ReplaceAll(info.Scope, " ", ", "))
	}
	if len(parts) == 0 {
		return "accepted by tokeninfo"
	}
	return strings.Join(parts, ", ")
}

// verifyRefreshToken exchanges the refresh token for an access token, which
// is not kept, with the client id and secret it was found with. A refresh
// token without its client cannot be checked: Google only accepts it from
// the client it was issued to.
func (p *Provider) verifyRefreshToken(ctx context.Context, tok detect.Token) detect.Verification {
	cred := decodeCredential(tok)
	if cred.ClientID == "" || cred.ClientSecret == "" {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "needs its OAuth client id and secret, which were not found next to it; Google only accepts a refresh token from the client it was issued to"}
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Value}, "client_id": {cred.ClientID}, "client_secret": {cred.ClientSecret}}
	status, body, err := p.post(ctx, p.TokenURL, form)
	if err != nil {
		return unknown(err.Error())
	}
	var e oauthError
	_ = json.Unmarshal(body, &e)
	client := "OAuth client " + clientPrefix(cred.ClientID)
	switch {
	case status == http.StatusOK:
		var granted struct {
			Scope string `json:"scope"`
		}
		_ = json.Unmarshal(body, &granted)
		detail := "refresh token accepted for " + client
		if granted.Scope != "" {
			detail += ", scopes: " + strings.ReplaceAll(granted.Scope, " ", ", ")
		}
		return detect.Verification{Status: detect.StatusActive, Detail: detail, ClientID: cred.ClientID}
	case status == http.StatusBadRequest && e.Error == "invalid_grant":
		return detect.Verification{Status: detect.StatusRevoked, Detail: "expired or revoked: " + e.Description}
	case status == http.StatusUnauthorized && e.Error == "invalid_client":
		return unknown("the client secret found next to it is not accepted for " + client + "; the token itself was not judged")
	}
	return unknown(httpError(status, e))
}

// apiError is the body of a rejected Google API request.
type apiError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// verifyAPIKey lists the Google APIs with the key. An unrestricted key is
// let through; a key restricted to other APIs is refused with 403, which
// still proves it exists; a deleted key is not valid.
func (p *Provider) verifyAPIKey(ctx context.Context, tok detect.Token) detect.Verification {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.DiscoveryURL+"?key="+url.QueryEscape(tok.Value), nil)
	if err != nil {
		return unknown(err.Error())
	}
	status, body, err := p.send(req)
	if err != nil {
		return unknown(err.Error())
	}
	var e apiError
	_ = json.Unmarshal(body, &e)
	switch status {
	case http.StatusOK:
		return detect.Verification{Status: detect.StatusActive, Detail: "unrestricted: accepted by the Discovery API"}
	case http.StatusForbidden:
		return detect.Verification{Status: detect.StatusActive, Detail: "restricted: the key exists but may not call the Discovery API (" + e.Error.Message + ")"}
	case http.StatusBadRequest:
		if strings.Contains(e.Error.Message, "API key not valid") {
			return detect.Verification{Status: detect.StatusRevoked, Detail: "deleted or never valid"}
		}
	}
	return unknown(fmt.Sprintf("HTTP %d: %s", status, e.Error.Message))
}

// post sends one form-encoded request and reads its answer.
func (p *Provider) post(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return p.send(req)
}

func (p *Provider) send(req *http.Request) (int, []byte, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, detect.ReadBody(io.Reader(resp.Body), 1<<20), nil
}

func httpError(status int, e oauthError) string {
	msg := fmt.Sprintf("HTTP %d", status)
	if e.Error != "" {
		msg += ": " + e.Error
	}
	if e.Description != "" {
		msg += " (" + e.Description + ")"
	}
	return msg
}

func unknown(detail string) detect.Verification {
	return detect.Verification{Status: detect.StatusUnknown, Detail: detail}
}
