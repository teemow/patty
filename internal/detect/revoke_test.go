package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevoke(t *testing.T) {
	var batches [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/credentials/revoke" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("revocation must be unauthenticated")
		}
		var body struct {
			Credentials []string `json:"credentials"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.Credentials) > 0 && body.Credentials[0] == "spam" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message":"Validation Failed"}`))
			return
		}
		batches = append(batches, body.Credentials)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	rv := &Revoker{BaseURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()

	tokens := make([]string, revokeBatch+2)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("t%d", i)
	}
	if err := rv.Revoke(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[0]) != revokeBatch || len(batches[1]) != 2 || batches[1][1] != tokens[revokeBatch+1] {
		t.Fatalf("batches: %d", len(batches))
	}
	if err := rv.Revoke(ctx, nil); err != nil || len(batches) != 2 {
		t.Fatalf("empty list must not call the API: %v", err)
	}
	if err := rv.Revoke(ctx, []string{"spam"}); err == nil || err.Error() != "revocation refused: HTTP 422: Validation Failed" {
		t.Fatalf("refused: %v", err)
	}
}

func TestRevocableAndRevokePage(t *testing.T) {
	for kind, want := range map[Kind]bool{KindPAT: true, KindFineGrained: true, KindOAuth: true, KindUserToServer: true, KindRefresh: true, KindServerToServer: false, Kind("x"): false} {
		if Revocable(kind) != want {
			t.Errorf("Revocable(%s) = %v", kind, !want)
		}
	}
	for _, kind := range []Kind{KindPAT, KindFineGrained, KindOAuth, KindUserToServer, KindRefresh, KindServerToServer} {
		if RevokePage(kind) == "" {
			t.Errorf("no revoke page for %s", kind)
		}
	}
	if RevokePage(Kind("x")) != "" {
		t.Error("unknown kind has no page")
	}
}
