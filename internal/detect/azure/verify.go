package azure

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/jwt"
)

// graphScope is what the client-credentials request asks for; every
// application may ask, and the token it gets is discarded.
const graphScope = "https://graph.microsoft.com/.default"

// storageSuffixes are the domains a signature's URL has to be under to be
// contacted: the public cloud and the sovereign ones. A repository must not
// be able to point patty at a server of its choosing.
var storageSuffixes = []string{".core.windows.net", ".core.chinacloudapi.cn", ".core.usgovcloudapi.net"}

// aadError is the body of a rejected token request. The description starts
// with the AADSTS code, which is also listed in error_codes.
type aadError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
	Codes       []int  `json:"error_codes"`
}

var aadstsCode = regexp.MustCompile(`AADSTS\d+`)

// code returns the AADSTS code of the answer: the first of error_codes, or
// the one the description starts with.
func (e aadError) code() string {
	if len(e.Codes) > 0 {
		return fmt.Sprintf("AADSTS%d", e.Codes[0])
	}
	return aadstsCode.FindString(e.Description)
}

// Verify implements detect.Provider with one request per credential: a
// client-credentials grant for a client secret, a signed container listing
// for a storage key, a HEAD of the resource for a signature. Only Azure's
// explicit rejections of the credential count as revoked.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	switch tok.Kind {
	case KindClientSecret:
		return p.verifyClientSecret(ctx, tok)
	case KindStorageAccountKey:
		return p.verifyStorageKey(ctx, tok)
	case KindSASToken:
		return p.verifySAS(ctx, tok)
	}
	return unknown("no check for " + string(tok.Kind))
}

// verifyClientSecret asks the tenant's token endpoint for a Graph token
// with the secret. The AADSTS codes tell an invalid secret and an expired
// one (revoked) from an application the tenant does not know and a tenant
// that does not exist (unknown: the id found nearby may be the wrong one).
func (p *Provider) verifyClientSecret(ctx context.Context, tok detect.Token) detect.Verification {
	pr := decodePrincipal(tok)
	switch {
	case pr.Tenant == "" && pr.Client == "":
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "tenant and client id not found near the secret; a secret is only accepted together with both"}
	case pr.Tenant == "":
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "tenant id not found near the secret; a secret is only accepted at its tenant's token endpoint"}
	case pr.Client == "":
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "client id not found near the secret; a secret is only accepted together with its application's id"}
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {pr.Client}, "client_secret": {tok.Value}, "scope": {graphScope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.LoginURL+"/"+url.PathEscape(pr.Tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return unknown(err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	status, _, body, err := p.send(req)
	if err != nil {
		return unknown(err.Error())
	}
	who := "app " + pr.Client + " in tenant " + pr.Tenant
	if status == http.StatusOK {
		var granted struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.Unmarshal(body, &granted)
		v := detect.Verification{Status: detect.StatusActive, Detail: who, ClientID: pr.Client}
		if claims, ok := jwt.Decode(granted.AccessToken); ok {
			v.App = claims.String("app_displayname")
			if id := claims.String("appid"); id != "" {
				v.ClientID = id
			}
		}
		return v
	}
	var e aadError
	_ = json.Unmarshal(body, &e)
	switch code := e.code(); code {
	case "AADSTS7000215":
		return detect.Verification{Status: detect.StatusRevoked, Detail: "invalid client secret for " + who}
	case "AADSTS7000222":
		return detect.Verification{Status: detect.StatusRevoked, Detail: "the client secret has expired (" + who + ")"}
	case "AADSTS700016":
		return unknown("app " + pr.Client + " not found in tenant " + pr.Tenant + "; wrong tenant id nearby?")
	case "AADSTS90002":
		return unknown("tenant " + pr.Tenant + " not found; wrong tenant id nearby?")
	case "":
		return unknown(fmt.Sprintf("HTTP %d: %s", status, firstLine(e.Description)))
	default:
		return unknown(code + ": " + firstLine(e.Description))
	}
}

// firstLine is the part of an AADSTS description before the trace and
// correlation ids, which is what the user can act on.
func firstLine(desc string) string {
	line, _, _ := strings.Cut(desc, "\r\n")
	line, _, _ = strings.Cut(line, "\n")
	line, _, _ = strings.Cut(line, " Trace ID:")
	return strings.TrimSpace(line)
}

// storageError is the body of a rejected storage request; the code is also
// in the x-ms-error-code header, which a HEAD answer has to carry instead.
type storageError struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// verifyStorageKey lists the account's containers with one Shared Key
// signed request, which every account key may make. A key the service no
// longer knows fails authentication; an account that is gone answers 404
// or does not resolve.
func (p *Provider) verifyStorageKey(ctx context.Context, tok detect.Token) detect.Verification {
	account := tok.Secret
	if account == "" {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "storage account name not found near the key"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.ReplaceAll(p.BlobEndpoint, "{account}", account)+"/?comp=list", nil)
	if err != nil {
		return unknown(err.Error())
	}
	if err := signSharedKey(req, account, tok.Value, p.now()); err != nil {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "malformed key: " + err.Error()}
	}
	status, header, body, err := p.send(req)
	if err != nil {
		var dns *net.DNSError
		if errors.As(err, &dns) && dns.IsNotFound {
			return unknown("storage account " + account + " does not resolve: it may have been deleted, or this machine cannot look it up")
		}
		return unknown(err.Error())
	}
	who := "storage account " + account
	code := errorCode(header, body)
	switch {
	case status == http.StatusOK:
		return detect.Verification{Status: detect.StatusActive, Detail: fmt.Sprintf("%s, %s", who, containers(body))}
	case status == http.StatusForbidden && code == "AuthenticationFailed":
		return detect.Verification{Status: detect.StatusRevoked, Detail: "key rotated: " + who + " no longer accepts it"}
	case status == http.StatusForbidden && code != "":
		return unknown(who + " refused the request before judging the key (" + code + "): a firewall or network rule, or Shared Key access is disabled on the account")
	case status == http.StatusNotFound:
		return detect.Verification{Status: detect.StatusRevoked, Detail: who + " does not exist any more (HTTP 404" + codeSuffix(code) + ")"}
	}
	return unknown(fmt.Sprintf("HTTP %d from %s%s", status, who, codeSuffix(code)))
}

func codeSuffix(code string) string {
	if code == "" {
		return ""
	}
	return ", " + code
}

// containers counts the containers a listing names.
func containers(body []byte) string {
	var list struct {
		Containers []struct {
			Name string `xml:"Name"`
		} `xml:"Containers>Container"`
	}
	if xml.Unmarshal(body, &list) != nil {
		return "containers listed"
	}
	n := len(list.Containers)
	if n == 1 {
		return "1 container"
	}
	return fmt.Sprintf("%d containers", n)
}

// errorCode reads the storage error code from the header, else the body.
func errorCode(header http.Header, body []byte) string {
	if code := header.Get("x-ms-error-code"); code != "" {
		return code
	}
	var e storageError
	_ = xml.Unmarshal(body, &e)
	return e.Code
}

// verifySAS checks a signature's expiry, which is in the token, and then
// sends one HEAD to the resource with it when the token came with its
// URL. A bare token has no resource to be checked against.
func (p *Provider) verifySAS(ctx context.Context, tok detect.Token) detect.Verification {
	s, ok := parseSignature(tok.Secret)
	if !ok {
		return unknown("the signature's parameters did not parse")
	}
	if !s.Expires.IsZero() && s.Expires.Before(p.now()) {
		return detect.Verification{Status: detect.StatusRevoked, Detail: "expired on " + s.Expires.UTC().Format("2006-01-02") + "; no storage service accepts an expired signature"}
	}
	if s.Resource == "" {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "bare token: only a full URL says which resource to ask"}
	}
	u, err := url.Parse(s.Raw)
	if err != nil || u.Host == "" {
		return unknown("resource URL does not parse")
	}
	if u.Scheme != "https" || !storageHost(u.Hostname()) {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: u.Host + " is not an https Azure Storage endpoint, not checked"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.Raw, nil)
	if err != nil {
		return unknown(err.Error())
	}
	status, header, body, err := p.send(req)
	if err != nil {
		return unknown(err.Error())
	}
	resource := u.Host + u.Path
	code := errorCode(header, body)
	switch {
	case status >= 200 && status < 300:
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted by " + resource, Expires: expiry(s)}
	case status == http.StatusForbidden && code == "AuthenticationFailed":
		return detect.Verification{Status: detect.StatusRevoked, Detail: resource + " rejects the signature: the key that signed it was rotated, or its access policy is gone"}
	case status == http.StatusForbidden && strings.HasPrefix(code, "Authorization"):
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted by " + resource + ", but not permitted to read it (" + code + ")", Expires: expiry(s)}
	case status == http.StatusNotFound:
		return unknown("the signature was not rejected, but " + resource + " does not exist (HTTP 404" + codeSuffix(code) + ")")
	}
	return unknown(fmt.Sprintf("HTTP %d from %s%s", status, resource, codeSuffix(code)))
}

func expiry(s signature) string {
	if s.Expires.IsZero() {
		return ""
	}
	return s.Expires.UTC().Format("2006-01-02")
}

// storageHost reports whether host is a storage endpoint of one of the
// Azure clouds.
func storageHost(host string) bool {
	for _, suffix := range storageSuffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return true
		}
	}
	return false
}

// send makes the one request and reads its answer.
func (p *Provider) send(req *http.Request) (int, http.Header, []byte, error) {
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, resp.Header, detect.ReadBody(resp.Body, 1<<20), nil
}

func unknown(detail string) detect.Verification {
	return detect.Verification{Status: detect.StatusUnknown, Detail: detail}
}
