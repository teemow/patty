package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// server fakes slack.com/api and hooks.slack.com: the bearer token or the
// webhook path decides the answer.
func server(t *testing.T) (*Provider, *[]string) {
	t.Helper()
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		calls = append(calls, r.Method+" "+r.URL.Path+" "+tok+" "+r.Form.Get("test"))
		if r.Method != http.MethodPost {
			t.Errorf("Slack methods are posted, got %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/auth.test":
			switch tok {
			case "live":
				w.Header().Set("X-OAuth-Scopes", "chat:write,channels:read")
				_, _ = w.Write([]byte(`{"ok":true,"team":"acme","user":"jane","team_id":"T1","user_id":"U1"}`))
			case "livebot":
				w.Header().Set("X-OAuth-Client-Id", "12345.67890")
				_, _ = w.Write([]byte(`{"ok":true,"team":"acme","user":"deploybot","bot_id":"B1"}`))
			case "dead":
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
			case "revoked":
				_, _ = w.Write([]byte(`{"ok":false,"error":"token_revoked"}`))
			case "inactive":
				_, _ = w.Write([]byte(`{"ok":false,"error":"account_inactive"}`))
			case "wrongtype":
				_, _ = w.Write([]byte(`{"ok":false,"error":"not_allowed_token_type"}`))
			case "ratelimited":
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"ok":false,"error":"ratelimited"}`))
			default:
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte("<html>upstream error</html>"))
			}
		case "/api/auth.revoke":
			switch tok {
			case "live", "livebot":
				_, _ = w.Write([]byte(`{"ok":true,"revoked":` + map[bool]string{true: "false", false: "true"}[r.Form.Get("test") == "1"] + `}`))
			case "stubborn":
				_, _ = w.Write([]byte(`{"ok":true,"revoked":false}`))
			default:
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
			}
		default: // webhooks
			if body := make([]byte, 2); r.Body != nil {
				n, _ := r.Body.Read(body)
				if string(body[:n]) != "{}" {
					t.Errorf("webhook verification must post an empty object, got %q", body[:n])
				}
			}
			switch {
			case strings.HasSuffix(r.URL.Path, "/live"):
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("invalid_payload"))
			case strings.HasSuffix(r.URL.Path, "/empty"):
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("missing_text_or_fallback_or_attachments"))
			case strings.HasSuffix(r.URL.Path, "/gone"):
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("no_service"))
			case strings.HasSuffix(r.URL.Path, "/noteam"):
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("no_team"))
			case strings.HasSuffix(r.URL.Path, "/badtoken"):
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("invalid_token"))
			default:
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("server_error"))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return &Provider{APIURL: srv.URL + "/api", HooksURL: srv.URL, Client: srv.Client()}, &calls
}

func TestVerifyTokens(t *testing.T) {
	p, _ := server(t)
	ctx := context.Background()
	cases := []struct {
		name   string
		tok    detect.Token
		status detect.VerifyStatus
		detail string
		client string
	}{
		{"user", detect.Token{Kind: KindUser, Value: "live"}, detect.StatusActive, "team acme, user jane, scopes: chat:write, channels:read", ""},
		{"bot", detect.Token{Kind: KindBot, Value: "livebot"}, detect.StatusActive, "team acme, bot deploybot", "12345.67890"},
		{"invalid_auth", detect.Token{Kind: KindBot, Value: "dead"}, detect.StatusRevoked, "", ""},
		{"token_revoked", detect.Token{Kind: KindUser, Value: "revoked"}, detect.StatusRevoked, "", ""},
		{"account_inactive", detect.Token{Kind: KindUser, Value: "inactive"}, detect.StatusRevoked, "the user or bot account was deactivated", ""},
		{"app token wrong type", detect.Token{Kind: KindApp, Value: "wrongtype"}, detect.StatusActive, "token accepted; auth.test does not describe this token type", ""},
		{"config token wrong type", detect.Token{Kind: KindConfig, Value: "wrongtype"}, detect.StatusActive, "token accepted; auth.test does not describe this token type", ""},
		{"bot token wrong type", detect.Token{Kind: KindBot, Value: "wrongtype"}, detect.StatusUnknown, "auth.test: not_allowed_token_type", ""},
		{"rate limited", detect.Token{Kind: KindBot, Value: "ratelimited"}, detect.StatusUnknown, "auth.test: ratelimited", ""},
		{"garbage", detect.Token{Kind: KindBot, Value: "upstream"}, detect.StatusUnknown, "HTTP 502 from auth.test", ""},
		{"refresh", detect.Token{Kind: KindRefresh, Value: "r"}, detect.StatusUnverifiable, "refresh tokens are only exchanged for new access tokens; rotating one would replace the live token", ""},
	}
	for _, c := range cases {
		got := p.Verify(ctx, c.tok)
		if got.Status != c.status || got.Detail != c.detail || got.ClientID != c.client {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

func TestVerifyWebhooks(t *testing.T) {
	p, calls := server(t)
	ctx := context.Background()
	url := func(last string) string { return hooksOrigin + "/services/" + teamID + "/" + botID + "/" + last }
	for last, want := range map[string]detect.VerifyStatus{
		"live": detect.StatusActive, "empty": detect.StatusActive,
		"gone": detect.StatusRevoked, "noteam": detect.StatusRevoked, "badtoken": detect.StatusRevoked,
		"broken": detect.StatusUnknown,
	} {
		if got := p.Verify(ctx, detect.Token{Kind: KindWebhook, Value: url(last)}); got.Status != want {
			t.Errorf("%s: %+v", last, got)
		}
	}
	for _, c := range *calls {
		if !strings.Contains(c, "/services/"+teamID+"/"+botID+"/") {
			t.Errorf("webhook must be posted to its own path, got %q", c)
		}
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindWebhook, Value: "https://example.invalid/hook"}); got.Status != detect.StatusUnknown {
		t.Fatalf("foreign URL: %+v", got)
	}
}

func TestRevoke(t *testing.T) {
	p, calls := server(t)
	ctx := context.Background()
	if err := p.Revoke(ctx, []string{"live", "livebot"}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 || (*calls)[0] != "POST /api/auth.revoke live " || (*calls)[1] != "POST /api/auth.revoke livebot " {
		t.Fatalf("calls: %q", *calls)
	}
	err := p.Revoke(ctx, []string{"dead", "stubborn"})
	if err == nil || !strings.Contains(err.Error(), "Slack refused the revocation: invalid_auth") || !strings.Contains(err.Error(), "did not revoke the token") {
		t.Fatalf("errors must be reported per token: %v", err)
	}
	if err := p.Revoke(ctx, []string{bot()}); err == nil || strings.Contains(err.Error(), alnum24) {
		t.Fatalf("errors must name the token redacted: %v", err)
	}
	if err := p.Revoke(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func TestDryRunRevoke(t *testing.T) {
	p, calls := server(t)
	ctx := context.Background()
	var _ detect.DryRunRevoker = p
	if err := p.DryRunRevoke(ctx, "live"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 || (*calls)[0] != "POST /api/auth.revoke live 1" {
		t.Fatalf("dry run must send test=1, got %q", *calls)
	}
	if err := p.DryRunRevoke(ctx, "dead"); err == nil || !strings.Contains(err.Error(), "invalid_auth") {
		t.Fatalf("dry run reports the refusal: %v", err)
	}
}
