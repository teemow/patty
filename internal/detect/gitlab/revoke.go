package gitlab

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Revoker for personal access tokens through
// DELETE /personal_access_tokens/self, authenticated with the token
// itself, on the first candidate instance that accepts it: the token does
// not say which GitLab issued it, so an instance that answers 401 is not
// the one and the next is tried. A 204 means the token is revoked; the
// caller confirms with Verify. No other family revokes itself.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	return detect.RevokeEach(ctx, tokens, func(ctx context.Context, tok detect.Token) error {
		if tok.Kind != KindPAT {
			return errors.New(string(tok.Kind) + " credentials cannot be revoked through the API; the report says where the owner does it")
		}
		var errs []error
		v := p.across(ctx, decode(tok).Instances, func(instance string) detect.Verification {
			status, err := p.deleteSelf(ctx, instance, tok.Value)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", detect.HostOf(instance), err))
				return detect.Unknown(err.Error())
			case status == http.StatusNoContent:
				return detect.Verification{Status: detect.StatusActive}
			case status == http.StatusUnauthorized:
				return detect.Verification{Status: detect.StatusRevoked}
			}
			errs = append(errs, fmt.Errorf("%s: revocation refused: HTTP %d", detect.HostOf(instance), status))
			return detect.Unknown("")
		})
		switch v.Status {
		case detect.StatusActive:
			return nil
		case detect.StatusRevoked:
			return errors.New("no candidate instance accepts the token any more")
		}
		return errors.Join(errs...)
	})
}

// DryRunRevoke implements detect.DryRunRevoker: it authenticates with the
// token on the candidate instances, exactly what Revoke does before
// deleting, and stops there.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	if tok.Kind != KindPAT {
		return errors.New(string(tok.Kind) + " credentials cannot be revoked through the API")
	}
	v := p.Verify(ctx, tok)
	switch v.Status {
	case detect.StatusActive:
		return nil
	case detect.StatusRevoked:
		return errors.New("no candidate instance accepts it any more")
	}
	return errors.New(v.Detail)
}

func (p *Provider) deleteSelf(ctx context.Context, instance, token string) (int, error) {
	resp, err := p.do(ctx, http.MethodDelete, instance+selfPath, token, "")
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}
