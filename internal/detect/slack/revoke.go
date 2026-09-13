package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Revoker through auth.revoke, one call per
// token: the token authenticates the request that revokes it. Slack answers
// `ok: true, revoked: true` and rejects the token from then on; unlike
// GitHub it does not notify anyone.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	return detect.RevokeEach(ctx, tokens, func(ctx context.Context, tok detect.Token) error {
		return p.revoke(ctx, tok.Value, false)
	})
}

// DryRunRevoke implements detect.DryRunRevoker with auth.revoke's test
// mode: Slack answers exactly as it would for the real request but leaves
// the token alone.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	if err := p.revoke(ctx, tok.Value, true); err != nil {
		return fmt.Errorf("%s: %w", detect.Redact(tok.Value), err)
	}
	return nil
}

func (p *Provider) revoke(ctx context.Context, token string, dryRun bool) error {
	form := ""
	if dryRun {
		form = "test=1"
	}
	resp, err := p.call(ctx, "auth.revoke", token, form)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var r apiResponse
	if json.Unmarshal(detect.ReadBody(resp.Body, 4096), &r) != nil {
		return fmt.Errorf("HTTP %d from auth.revoke", resp.StatusCode)
	}
	switch {
	case !r.OK:
		return errors.New("Slack refused the revocation: " + r.Error)
	case !dryRun && !r.Revoked:
		return errors.New("Slack accepted the request but did not revoke the token") //nolint:staticcheck // Slack is a proper noun
	}
	return nil
}
