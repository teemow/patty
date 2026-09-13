package pagerduty

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestVerifyAPIKey(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		if r.Header.Get("Accept") != accept || r.Header.Get("User-Agent") != detect.UserAgent {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := r.Header.Get("Authorization")
		switch {
		case key == "Token token=user" && r.URL.Path == mePath:
			_, _ = w.Write([]byte(`{"user":{"name":"Jane Doe","email":"jane@example.com","role":"admin"}}`))
		case key == "Token token=general" && r.URL.Path == mePath:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"Requesting user not found","code":2001}}`))
		case key == "Token token=general" && r.URL.Path == abilitiesPath:
			_, _ = w.Write([]byte(`{"abilities":["teams"]}`))
		case key == "Token token=busy":
			w.WriteHeader(http.StatusTooManyRequests)
		case key == "Token token=odd":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	p := &Provider{BaseURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()

	if got := p.Verify(ctx, detect.Token{Kind: KindAPIKey, Value: "user"}); got.Status != detect.StatusActive || got.Detail != "user Jane Doe jane@example.com, role admin" {
		t.Fatalf("user key: %+v", got)
	}
	calls = nil
	if got := p.Verify(ctx, detect.Token{Kind: KindAPIKey, Value: "general"}); got.Status != detect.StatusActive || got.Detail != "general access key (account-level)" || len(calls) != 2 || calls[1] != abilitiesPath {
		t.Fatalf("general key: %+v, calls %v", got, calls)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindAPIKey, Value: "dead"}); got.Status != detect.StatusRevoked {
		t.Fatalf("dead: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindAPIKey, Value: "busy"}); got.Status != detect.StatusUnknown || got.Detail != "rate limited" {
		t.Fatalf("busy: %+v", got)
	}
	if got := p.Verify(ctx, detect.Token{Kind: KindAPIKey, Value: "odd"}); got.Status != detect.StatusUnknown {
		t.Fatalf("odd: %+v", got)
	}
}

// noNetwork is a transport that fails the test on any request.
type noNetwork struct{ t *testing.T }

func (n noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("a request was made to %s", r.URL)
	return nil, errors.New("no network in this test")
}

func TestRoutingKeyIsNeverSent(t *testing.T) {
	p := New()
	p.Client = &http.Client{Transport: noNetwork{t}}
	got := p.Verify(context.Background(), detect.Token{Kind: KindRoutingKey, Value: hex32})
	if got.Status != detect.StatusUnverifiable || got.Detail != "verifying would page the on-call; treat as live" {
		t.Fatalf("routing key: %+v", got)
	}
}
