package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/teemow/patty/internal/detect"
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
	p := &Provider{BaseURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()

	tokens := make([]detect.Token, revokeBatch+2)
	for i := range tokens {
		tokens[i] = detect.Token{Kind: KindPAT, Value: fmt.Sprintf("t%d", i)}
	}
	if err := p.Revoke(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 2 || len(batches[0]) != revokeBatch || len(batches[1]) != 2 || batches[1][1] != tokens[revokeBatch+1].Value {
		t.Fatalf("batches: %d", len(batches))
	}
	if err := p.Revoke(ctx, nil); err != nil || len(batches) != 2 {
		t.Fatalf("empty list must not call the API: %v", err)
	}
	if err := p.Revoke(ctx, []detect.Token{{Kind: KindPAT, Value: "spam"}}); err == nil || err.Error() != "revocation refused: HTTP 422: Validation Failed" {
		t.Fatalf("refused: %v", err)
	}
}
