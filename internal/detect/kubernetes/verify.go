package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/jwt"
)

// versionPath is the one endpoint --verify reads: it needs no permission
// beyond authentication and names the cluster's version.
const versionPath = "/version"

// Verify implements detect.Provider with one GET /version against the
// server the kubeconfig names, with the credential. A credential that
// carries its own expiry, a certificate or a bound token, and has passed
// it is dead without asking anyone. A credential found without a server,
// or a Secret manifest, cannot be checked. A 401, a 403 that ran as
// system:anonymous, and a TLS handshake the server refuses because of the
// certificate are the explicit rejections; anything else that is not a
// clean 200 is unknown, an unreachable server included.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	if tok.Kind == KindSecretManifest {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "opaque secret material; rotate whatever it protects"}
	}
	cred := decodeCredential(tok)
	var (
		cert    certificate
		summary string
	)
	switch tok.Kind {
	case KindClientCertificate:
		c, ok := parsePEM([]byte(cred.Cert), []byte(cred.Key))
		if !ok {
			return unknown("the certificate or its key did not parse")
		}
		cert, summary = c, "CN="+c.Subject
		if c.Expired() {
			return detect.Verification{Status: detect.StatusRevoked, Detail: "expired on " + day(c.NotAfter) + "; no API server accepts an expired certificate"}
		}
	case KindServiceAccountToken:
		if claims, ok := jwt.Decode(tok.Value); ok && claims.Expired(time.Now()) {
			return detect.Verification{Status: detect.StatusRevoked, Detail: "expired on " + day(claims.Expires) + "; a bound token is not accepted past its expiry"}
		}
	}
	if cred.Server == "" {
		return detect.Verification{Status: detect.StatusUnverifiable, Detail: "no server named next to it: only a kubeconfig says which API server to ask"}
	}
	if v, ok := p.policy().Admit(ctx, cred.Server); !ok {
		return v
	}
	client, err := p.client(cred, cert)
	if err != nil {
		return unknown(err.Error())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cred.Server, "/")+versionPath, nil)
	if err != nil {
		return unknown(err.Error())
	}
	req.Header.Set("Accept", "application/json")
	switch tok.Kind {
	case KindToken, KindServiceAccountToken:
		req.Header.Set("Authorization", "Bearer "+tok.Value)
	case KindBasicAuth:
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password)))
	}
	resp, err := detect.Do(client, req)
	if err != nil {
		if tok.Kind == KindClientCertificate {
			if alert, ok := certificateAlert(err); ok {
				return detect.Verification{Status: detect.StatusRevoked, Detail: "the server refused the certificate in the TLS handshake (" + alert + ")"}
			}
		}
		return unknown("server not reachable from here: " + err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	body := detect.ReadBody(resp.Body, 1<<20)
	host := hostOf(cred.Server)
	switch resp.StatusCode {
	case http.StatusOK:
		detail := "accepted by " + host
		if v := gitVersion(body); v != "" {
			detail += ", Kubernetes " + v
		}
		if summary != "" {
			detail += ", as " + summary
		}
		return detect.Verification{Status: detect.StatusActive, Detail: detail}
	case http.StatusUnauthorized:
		return detect.Verification{Status: detect.StatusRevoked, Detail: host + " rejects it"}
	case http.StatusForbidden:
		msg := statusMessage(body)
		if strings.Contains(msg, "system:anonymous") {
			return detect.Verification{Status: detect.StatusRevoked, Detail: host + " did not accept it: the request ran as system:anonymous"}
		}
		return detect.Verification{Status: detect.StatusActive, Detail: "accepted by " + host + ", but not allowed to read " + versionPath + ": " + msg}
	}
	return unknown(fmt.Sprintf("HTTP %d from %s", resp.StatusCode, host))
}

// client builds the one-shot HTTP client for a credential: the cluster's
// CA when the kubeconfig embeds one, else no verification when it says
// insecure-skip-tls-verify, else the system roots; and the client
// certificate when the credential is one.
func (p *Provider) client(cred credential, cert certificate) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cred.Insecure && cred.CA == ""} //nolint:gosec // the kubeconfig asked for it
	if cred.CA != "" {
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM([]byte(cred.CA)) {
			return nil, fmt.Errorf("the kubeconfig's certificate-authority-data does not parse")
		}
	}
	if cert.PEM != "" {
		pair, err := tls.X509KeyPair([]byte(cert.PEM), []byte(cert.KeyPEM))
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: p.Timeout, Transport: &http.Transport{TLSClientConfig: cfg, Proxy: http.ProxyFromEnvironment}}, nil
}

// certificateAlerts are the TLS alerts a server sends when it is the
// client's certificate it objects to.
var certificateAlerts = []string{"bad certificate", "unknown certificate authority", "certificate required", "expired certificate", "revoked certificate", "unknown certificate", "unsupported certificate"}

// certificateAlert reports whether the error is the server refusing the
// client certificate during the handshake, and which alert it sent. Go
// reports a remote alert as "remote error: tls: <alert>".
func certificateAlert(err error) (string, bool) {
	msg := err.Error()
	i := strings.Index(msg, "remote error: tls: ")
	if i < 0 {
		return "", false
	}
	alert := msg[i+len("remote error: tls: "):]
	for _, known := range certificateAlerts {
		if alert == known {
			return alert, true
		}
	}
	return "", false
}

func gitVersion(body []byte) string {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	_ = json.Unmarshal(body, &v)
	return v.GitVersion
}

// statusMessage reads the message of a Kubernetes Status object, the body
// of every error the API server returns; a body that is not one is
// returned as is, trimmed.
func statusMessage(body []byte) string {
	var s struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &s) == nil && s.Message != "" {
		return s.Message
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "…"
	}
	return msg
}

func unknown(detail string) detect.Verification { return detect.Unknown(detail) }
