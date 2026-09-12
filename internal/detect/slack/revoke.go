package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Provider through auth.revoke, one call per
// token: the token authenticates the request that revokes it. Slack answers
// `ok: true, revoked: true` and rejects the token from then on; unlike
// GitHub it does not notify anyone.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	var errs []error
	for _, tok := range tokens {
		if err := p.revoke(ctx, tok.Value, false); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DryRunRevoke implements detect.DryRunRevoker with auth.revoke's test
// mode: Slack answers exactly as it would for the real request but leaves
// the token alone.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	return p.revoke(ctx, tok.Value, true)
}

func (p *Provider) revoke(ctx context.Context, token string, dryRun bool) error {
	form := ""
	if dryRun {
		form = "test=1"
	}
	resp, err := p.call(ctx, "auth.revoke", token, form)
	if err != nil {
		return fmt.Errorf("%s: %w", detect.Redact(token), err)
	}
	defer func() { _ = resp.Body.Close() }()
	var r apiResponse
	if json.Unmarshal(detect.ReadBody(resp.Body, 4096), &r) != nil {
		return fmt.Errorf("%s: HTTP %d from auth.revoke", detect.Redact(token), resp.StatusCode)
	}
	switch {
	case !r.OK:
		return fmt.Errorf("%s: Slack refused the revocation: %s", detect.Redact(token), r.Error)
	case !dryRun && !r.Revoked:
		return fmt.Errorf("%s: Slack accepted the request but did not revoke the token", detect.Redact(token))
	}
	return nil
}
