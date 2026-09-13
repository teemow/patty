package npm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Revoker through the registry's token API, one
// DELETE per token, authenticated with the token itself: the endpoint
// `npm token revoke` uses accepts the token value as the key. A registry
// that only takes the record's key gets a second DELETE with the key the
// token list shows for it. A 200 or 204 means the token is gone; the
// caller confirms with Verify.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	return detect.RevokeEach(ctx, tokens, func(ctx context.Context, tok detect.Token) error {
		registry, v, ok := p.registry(ctx, tok)
		if !ok {
			return errors.New(v.Detail)
		}
		status, err := p.delete(ctx, registry, tok.Value, tok.Value)
		if err != nil {
			return err
		}
		if status == http.StatusNotFound {
			rec, err := p.lookup(ctx, registry, tok.Value)
			if err != nil {
				return fmt.Errorf("the registry does not know the token by its value and %w", err)
			}
			status, err = p.delete(ctx, registry, rec.Key, tok.Value)
			if err != nil {
				return err
			}
		}
		if status != http.StatusOK && status != http.StatusNoContent {
			return fmt.Errorf("revocation refused: HTTP %d", status)
		}
		return nil
	})
}

// DryRunRevoke implements detect.DryRunRevoker: it authenticates with the
// token and looks it up in the account's list, exactly what Revoke does
// before deleting, and stops there. A registry that does not list the
// token (granular tokens are not listed) still accepts the deletion by
// value, so that is not a failure.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	v := p.Verify(ctx, tok)
	switch v.Status {
	case detect.StatusActive:
		return nil
	case detect.StatusRevoked:
		return errors.New("the registry already rejects it")
	}
	return errors.New(v.Detail)
}

func (p *Provider) delete(ctx context.Context, registry, key, token string) (int, error) {
	resp, err := p.do(ctx, http.MethodDelete, registry+tokensPath+"/token/"+url.PathEscape(key), token)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}
