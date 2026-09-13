package privatekey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

// keysServer serves <login>.keys for the given logins.
func keysServer(t *testing.T, keys map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, ok := keys[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestCommittersMatchesPublishedKeys(t *testing.T) {
	ed, rsaK := ed25519Key(t), rsaKey(t)
	srv, calls := keysServer(t, map[string]string{
		"/octocat.keys": authorizedLine(t, ed.Public(), "") + "\n" + authorizedLine(t, rsaK.Public(), "") + "\n",
		"/hubot.keys":   authorizedLine(t, ed.Public(), "") + "\n",
	})
	p := New()
	p.KeysURL, p.Client = srv.URL+"/", srv.Client()
	got := p.Committers(context.Background(), []string{"octocat", "nobody", "hubot", "bad login!", ""})
	want := map[string]string{
		fingerprint(t, ed.Public()):   "matches octocat's GitHub SSH key",
		spki(t, ed.Public()):          "matches octocat's GitHub SSH key",
		fingerprint(t, rsaK.Public()): "matches octocat's GitHub SSH key",
		spki(t, rsaK.Public()):        "matches octocat's GitHub SSH key",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("%d requests, want one per valid login", n)
	}
	// A second repository with the same committers costs nothing.
	p.Committers(context.Background(), []string{"octocat", "nobody"})
	if n := calls.Load(); n != 3 {
		t.Fatalf("%d requests after the second call, want 3", n)
	}
	if login := p.loginOf(fingerprint(t, ed.Public())); login != "octocat" {
		t.Fatalf("loginOf = %q", login)
	}
	if p.loginOf("SHA256:unknown") != "" || !p.lookedUp() {
		t.Fatal("unknown key has no login")
	}
}

func TestCommittersWithoutClient(t *testing.T) {
	p := &Provider{}
	if got := p.Committers(context.Background(), []string{"octocat"}); len(got) != 0 {
		t.Fatalf("no client, got %v", got)
	}
}
