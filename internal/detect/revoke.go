package detect

import (
	"context"
	"errors"
	"fmt"
)

// RevokeEach revokes tokens one at a time with revoke and returns the
// failures joined, each prefixed with the redacted token it concerns, so a
// provider that refuses one credential still revokes the others. It is the
// Revoke loop of every provider whose API revokes a single credential per
// request.
func RevokeEach(ctx context.Context, tokens []Token, revoke func(context.Context, Token) error) error {
	var errs []error
	for _, tok := range tokens {
		if err := revoke(ctx, tok); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", Redact(tok.Value), err))
		}
	}
	return errors.Join(errs...)
}
