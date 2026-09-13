package detect

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRevokeEach(t *testing.T) {
	tokens := []Token{{Value: "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, {Value: "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}, {Value: "ghp_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}}
	var seen []string
	refused := errors.New("refused")
	err := RevokeEach(context.Background(), tokens, func(_ context.Context, tok Token) error {
		seen = append(seen, tok.Value)
		if tok.Value != tokens[1].Value {
			return refused
		}
		return nil
	})
	if len(seen) != 3 {
		t.Fatalf("every token must be tried even after a refusal, got %d", len(seen))
	}
	if !errors.Is(err, refused) || strings.Count(err.Error(), "refused") != 2 {
		t.Fatalf("failures must be joined and wrapped: %v", err)
	}
	for _, tok := range tokens {
		if strings.Contains(err.Error(), tok.Value) {
			t.Fatalf("errors must name the token redacted: %v", err)
		}
	}
	if !strings.HasPrefix(err.Error(), Redact(tokens[0].Value)+": refused") {
		t.Fatalf("each failure names its token: %v", err)
	}
	if err := RevokeEach(context.Background(), nil, func(context.Context, Token) error { return refused }); err != nil {
		t.Fatalf("nothing to revoke, nothing to report: %v", err)
	}
}
