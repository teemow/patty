package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teemow/patty/internal/detect"
)

const (
	liveToken = "live-token-0123456789abcdef"
	deadToken = "dead-token-0123456789abcdef"
	anonymous = `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"/version\"","reason":"Forbidden","details":{},"code":403}`
	limited   = `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"limited\" cannot get path \"/version\"","reason":"Forbidden","details":{},"code":403}`
)

// apiServer fakes GET /version behind TLS with optional client
// certificates. A certificate's common name decides its fate: "anon" is
// treated as not accepted, "limited" as accepted but forbidden, anything
// else as a live identity. Bearer and Basic credentials are looked up.
func apiServer(t *testing.T, ca *authority) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != versionPath || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if !strings.Contains(r.Header.Get("User-Agent"), detect.UserAgent) {
			t.Errorf("User-Agent %q does not name patty", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		ok := func() {
			_, _ = w.Write([]byte(`{"major":"1","minor":"31","gitVersion":"v1.31.2","platform":"linux/amd64"}`))
		}
		if certs := r.TLS.PeerCertificates; len(certs) > 0 {
			switch certs[0].Subject.CommonName {
			case "anon":
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(anonymous))
			case "limited":
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(limited))
			default:
				ok()
			}
			return
		}
		auth := r.Header.Get("Authorization")
		user, pass, basic := r.BasicAuth()
		switch {
		case auth == "Bearer "+liveToken, basic && user == "jane" && pass == "correct-horse":
			ok()
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"Unauthorized","reason":"Unauthorized","code":401}`))
		}
	}))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &requests
}

// serverCA is the PEM of the certificate the test server presents, which a
// kubeconfig would carry as certificate-authority-data.
func serverCA(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func local(t *testing.T) *Provider {
	t.Helper()
	p := New()
	p.AllowPrivateServers(true)
	return p
}

// only returns the one token a kubeconfig yields.
func only(t *testing.T, content string) detectToken {
	t.Helper()
	got := find([]byte(content))
	if len(got) != 1 {
		t.Fatalf("want one token, got %+v", redactAll(got))
	}
	return got[0]
}

func TestVerifyClientCertificate(t *testing.T) {
	ca := newAuthority(t, "kubernetes")
	srv, requests := apiServer(t, ca)
	p := local(t)
	future := time.Now().Add(365 * 24 * time.Hour)
	for _, c := range []struct {
		name, cn string
		status   detect.VerifyStatus
		detail   string
	}{
		{"accepted", "kubernetes-admin", detect.StatusActive, "Kubernetes v1.31.2, as CN=kubernetes-admin"},
		{"not accepted", "anon", detect.StatusRevoked, "ran as system:anonymous"},
		{"forbidden", "limited", detect.StatusActive, "not allowed to read /version"},
	} {
		certPEM, keyPEM := ca.client(t, c.cn, []string{"system:masters"}, future)
		tok := only(t, kubeconfig(srv.URL, serverCA(srv), false, certUser("u", certPEM, keyPEM)))
		got := p.Verify(context.Background(), tok)
		if got.Status != c.status || !strings.Contains(got.Detail, c.detail) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if requests.Load() != 3 {
		t.Fatalf("one request per certificate, got %d", requests.Load())
	}
	// An expired certificate is dead without asking anyone.
	certPEM, keyPEM := ca.client(t, "old", nil, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	got := p.Verify(context.Background(), only(t, kubeconfig(srv.URL, serverCA(srv), false, certUser("u", certPEM, keyPEM))))
	if got.Status != detect.StatusRevoked || !strings.Contains(got.Detail, "expired on 2024-01-01") || requests.Load() != 3 {
		t.Fatalf("expired certificate: %+v after %d requests", got, requests.Load())
	}
}

func TestVerifyCertificateRefusedInHandshake(t *testing.T) {
	ours, theirs := newAuthority(t, "ours"), newAuthority(t, "theirs")
	srv, _ := apiServer(t, theirs)
	srv.TLS.ClientAuth = tls.RequireAndVerifyClientCert
	certPEM, keyPEM := ours.client(t, "admin", nil, time.Now().Add(time.Hour))
	got := local(t).Verify(context.Background(), only(t, kubeconfig(srv.URL, serverCA(srv), false, certUser("u", certPEM, keyPEM))))
	if got.Status != detect.StatusRevoked || !strings.Contains(got.Detail, "refused the certificate in the TLS handshake") {
		t.Fatalf("certificate of another CA: %+v", got)
	}
}

func TestVerifyTokensAndBasicAuth(t *testing.T) {
	ca := newAuthority(t, "kubernetes")
	srv, _ := apiServer(t, ca)
	p := local(t)
	for _, c := range []struct {
		name, user string
		status     detect.VerifyStatus
		detail     string
	}{
		{"live token", tokenUser("u", liveToken), detect.StatusActive, "accepted by 127.0.0.1"},
		{"dead token", tokenUser("u", deadToken), detect.StatusRevoked, "rejects it"},
		{"basic auth", basicUser("u", "jane", "correct-horse"), detect.StatusActive, "Kubernetes v1.31.2"},
		{"wrong password", basicUser("u", "jane", "wrong-password"), detect.StatusRevoked, "rejects it"},
	} {
		got := p.Verify(context.Background(), only(t, kubeconfig(srv.URL, serverCA(srv), false, c.user)))
		if got.Status != c.status || !strings.Contains(got.Detail, c.detail) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	// insecure-skip-tls-verify is honoured when no CA is given.
	got := p.Verify(context.Background(), only(t, kubeconfig(srv.URL, nil, true, tokenUser("u", liveToken))))
	if got.Status != detect.StatusActive {
		t.Fatalf("insecure kubeconfig: %+v", got)
	}
	// Without a CA and without insecure, the self-signed test server is not trusted: not reachable, not a verdict.
	got = p.Verify(context.Background(), only(t, kubeconfig(srv.URL, nil, false, tokenUser("u", liveToken))))
	if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "server not reachable from here") {
		t.Fatalf("untrusted server: %+v", got)
	}
}

func TestVerifyServiceAccountTokens(t *testing.T) {
	ca := newAuthority(t, "kubernetes")
	srv, requests := apiServer(t, ca)
	p := local(t)
	bare := legacyToken(t, "default", "builder")
	got := p.Verify(context.Background(), only(t, "token: "+bare+"\n"))
	if got.Status != detect.StatusUnverifiable || !strings.Contains(got.Detail, "no server") || requests.Load() != 0 {
		t.Fatalf("bare token: %+v", got)
	}
	expired := boundToken(t, "apps", "worker", "pod", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	got = p.Verify(context.Background(), only(t, kubeconfig(srv.URL, serverCA(srv), false, tokenUser("u", expired))))
	if got.Status != detect.StatusRevoked || !strings.Contains(got.Detail, "expired on 2024-01-01") || requests.Load() != 0 {
		t.Fatalf("expired bound token: %+v", got)
	}
	got = p.Verify(context.Background(), only(t, kubeconfig(srv.URL, serverCA(srv), false, tokenUser("u", bare))))
	if got.Status != detect.StatusRevoked || requests.Load() != 1 {
		t.Fatalf("legacy token in a kubeconfig is sent once: %+v", got)
	}
	if got := p.Verify(context.Background(), detect.Token{Kind: KindSecretManifest, Value: "ns/name"}); got.Status != detect.StatusUnverifiable || !strings.Contains(got.Detail, "opaque secret material") {
		t.Fatalf("secret manifest: %+v", got)
	}
}

func TestVerifyRefusesPrivateAndPlainServers(t *testing.T) {
	ca := newAuthority(t, "kubernetes")
	srv, requests := apiServer(t, ca)
	p := New() // private servers not allowed
	got := p.Verify(context.Background(), only(t, kubeconfig(srv.URL, serverCA(srv), false, tokenUser("u", liveToken))))
	if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "private network") || !strings.Contains(got.Detail, "--verify-private-servers") {
		t.Fatalf("loopback server: %+v", got)
	}
	for name, ips := range map[string][]net.IP{"private": {net.ParseIP("10.1.2.3")}, "link-local": {net.ParseIP("169.254.169.254")}, "mixed": {net.ParseIP("93.184.216.34"), net.ParseIP("192.168.1.1")}} {
		p.LookupIP = func(context.Context, string) ([]net.IP, error) { return ips, nil }
		got = p.Verify(context.Background(), only(t, kubeconfig(server, nil, true, tokenUser("u", liveToken))))
		if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "private network") {
			t.Errorf("%s: %+v", name, got)
		}
	}
	p.LookupIP = func(context.Context, string) ([]net.IP, error) { return nil, errors.New("no such host") }
	got = p.Verify(context.Background(), only(t, kubeconfig(server, nil, true, tokenUser("u", liveToken))))
	if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "not reachable") {
		t.Fatalf("unresolvable host: %+v", got)
	}
	got = p.Verify(context.Background(), only(t, kubeconfig("http://k8s.example.com:8080", nil, false, tokenUser("u", liveToken))))
	if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "not https") {
		t.Fatalf("plain http server: %+v", got)
	}
	if requests.Load() != 0 {
		t.Fatalf("a refused server must not be contacted, saw %d requests", requests.Load())
	}
}

func TestVerifyUnreachableIsUnknown(t *testing.T) {
	ca := newAuthority(t, "kubernetes")
	srv, _ := apiServer(t, ca)
	url := srv.URL
	srv.Close()
	p := local(t)
	p.Timeout = time.Second
	got := p.Verify(context.Background(), only(t, kubeconfig(url, nil, true, tokenUser("u", liveToken))))
	if got.Status != detect.StatusUnknown || !strings.Contains(got.Detail, "server not reachable from here") {
		t.Fatalf("closed server: %+v", got)
	}
	certPEM, keyPEM := ca.client(t, "admin", nil, time.Now().Add(time.Hour))
	got = p.Verify(context.Background(), only(t, kubeconfig(url, nil, true, certUser("u", certPEM, keyPEM))))
	if got.Status != detect.StatusUnknown {
		t.Fatalf("a connection error is never a verdict on a certificate: %+v", got)
	}
}
