package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// call is one signed request the fake AWS saw.
type call struct {
	action, keyID, session string
	form                   map[string]string
}

// server fakes the STS and IAM query APIs on one endpoint. The key id in
// the SigV4 Authorization header decides the answer; every key id but the
// "live-*" ones is an error scenario.
func server(t *testing.T) (*Provider, func() []call) {
	t.Helper()
	var (
		mu       sync.Mutex
		calls    []call
		inactive = map[string]bool{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodPost {
			t.Errorf("query APIs are posted, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") {
			t.Errorf("requests must be SigV4 signed, got %q", auth)
		}
		keyID, _, _ := strings.Cut(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 Credential="), "/")
		if !strings.Contains(auth, "/"+region+"/") {
			t.Errorf("signed for the wrong region: %q", auth)
		}
		if !strings.Contains(r.Header.Get("User-Agent"), detect.UserAgent) {
			t.Errorf("User-Agent %q does not name patty", r.Header.Get("User-Agent"))
		}
		_ = r.ParseForm()
		c := call{action: r.Form.Get("Action"), keyID: keyID, session: r.Header.Get("X-Amz-Security-Token"), form: map[string]string{}}
		for k := range r.Form {
			c.form[k] = r.Form.Get(k)
		}
		calls = append(calls, c)
		w.Header().Set("Content-Type", "text/xml")
		fail := func(status int, code, msg string) {
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>r</RequestId></ErrorResponse>`, code, msg)
		}
		switch {
		case inactive[keyID], keyID == "dead":
			fail(http.StatusForbidden, "InvalidClientTokenId", "The security token included in the request is invalid.")
			return
		case keyID == "wrongsecret":
			fail(http.StatusForbidden, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.")
			return
		case keyID == "expired":
			fail(http.StatusForbidden, "ExpiredToken", "The security token included in the request is expired")
			return
		case keyID == "throttled":
			fail(http.StatusBadRequest, "Throttling", "Rate exceeded")
			return
		case keyID == "broken":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html>upstream error</html>"))
			return
		}
		switch c.action {
		case "GetCallerIdentity":
			arn := map[string]string{
				"live-user":   "arn:aws:iam::123456789012:user/alice",
				"live-path":   "arn:aws:iam::123456789012:user/ops/tools/deploy",
				"live-role":   "arn:aws:sts::123456789012:assumed-role/Deploy/i-0abc",
				"live-root":   "arn:aws:iam::123456789012:root",
				"live-denied": "arn:aws:iam::123456789012:user/bob",
			}[keyID]
			if arn == "" {
				fail(http.StatusForbidden, "InvalidClientTokenId", "unknown test key")
				return
			}
			_, _ = fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>%s</Arn><UserId>AIDATEST</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`, arn)
		case "UpdateAccessKey":
			if keyID == "live-denied" {
				fail(http.StatusForbidden, "AccessDenied", "User: arn:aws:iam::123456789012:user/bob is not authorized to perform: iam:UpdateAccessKey")
				return
			}
			if c.form["Status"] == "Inactive" {
				inactive[c.form["AccessKeyId"]] = true
			}
			_, _ = w.Write([]byte(`<UpdateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></UpdateAccessKeyResponse>`))
		default:
			t.Errorf("unexpected action %q", c.action)
			fail(http.StatusBadRequest, "InvalidAction", c.action)
		}
	}))
	t.Cleanup(srv.Close)
	p := &Provider{STSURL: srv.URL, IAMURL: srv.URL, Client: srv.Client()}
	return p, func() []call {
		mu.Lock()
		defer mu.Unlock()
		return append([]call(nil), calls...)
	}
}

func pairOf(kind detect.Kind, id, secret string) detect.Token {
	return detect.Token{Kind: kind, Value: id, Secret: secret}
}

func TestVerify(t *testing.T) {
	p, calls := server(t)
	ctx := context.Background()
	cases := []struct {
		name   string
		tok    detect.Token
		status detect.VerifyStatus
		detail string
		calls  int
	}{
		{"id only", detect.Token{Kind: KindAccessKey, Value: "live-user"}, detect.StatusUnverifiable, "secret not found near the key id", 0},
		{"temporary without session token", pairOf(KindTemporaryKey, "live-user", mixed), detect.StatusUnverifiable, "session token not found near the key id; a temporary key is only accepted together with it", 0},
		{"live user", pairOf(KindAccessKey, "live-user", mixed), detect.StatusActive, "arn:aws:iam::123456789012:user/alice, account 123456789012", 1},
		{"live role session", pairOf(KindTemporaryKey, "live-role", mixed+"\n"+long), detect.StatusActive, "arn:aws:sts::123456789012:assumed-role/Deploy/i-0abc, account 123456789012", 1},
		{"deleted", pairOf(KindAccessKey, "dead", mixed), detect.StatusRevoked, "key deleted or deactivated", 1},
		{"temporary rejected", pairOf(KindTemporaryKey, "dead", mixed+"\n"+long), detect.StatusRevoked, "session token no longer accepted", 1},
		{"wrong secret", pairOf(KindAccessKey, "wrongsecret", mixed), detect.StatusUnknown, "key id exists but the secret found next to it is not its secret", 1},
		{"expired temporary", pairOf(KindTemporaryKey, "expired", mixed+"\n"+long), detect.StatusRevoked, "expired", 1},
		{"expired long-lived is unexpected", pairOf(KindAccessKey, "expired", mixed), detect.StatusUnknown, "ExpiredToken: The security token included in the request is expired", 1},
		{"throttled", pairOf(KindAccessKey, "throttled", mixed), detect.StatusUnknown, "Throttling: Rate exceeded", 1},
		{"server error is not retried", pairOf(KindAccessKey, "broken", mixed), detect.StatusUnknown, "", 1},
	}
	for _, c := range cases {
		before := len(calls())
		got := p.Verify(ctx, c.tok)
		if got.Status != c.status || (c.detail != "" && got.Detail != c.detail) || (c.detail == "" && got.Detail == "") {
			t.Errorf("%s: %+v", c.name, got)
		}
		made := calls()[before:]
		if len(made) != c.calls {
			t.Errorf("%s: %d calls, want %d: %+v", c.name, len(made), c.calls, made)
			continue
		}
		for _, m := range made {
			if m.action != "GetCallerIdentity" || m.form["Version"] != "2011-06-15" || m.keyID != c.tok.Value {
				t.Errorf("%s: unexpected call %+v", c.name, m)
			}
			_, session := credentials(c.tok)
			if m.session != session {
				t.Errorf("%s: session token header %q, want %q", c.name, m.session, session)
			}
		}
	}
}

func TestVerifyNetworkErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	p := &Provider{STSURL: srv.URL, IAMURL: srv.URL, Client: srv.Client()}
	got := p.Verify(context.Background(), pairOf(KindAccessKey, akia(), mixed))
	if got.Status != detect.StatusUnknown || got.Detail == "" {
		t.Fatalf("unreachable STS: %+v", got)
	}
	if strings.Contains(got.Detail, mixed) {
		t.Fatal("the secret must never appear in a detail")
	}
}
