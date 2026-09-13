package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Revoker through Google's revoke endpoint, which
// accepts an access or a refresh token from whoever holds it and revokes
// the grant both belong to; no client secret is needed. A token Google
// already rejects counts as done, Verify confirms it afterwards. Service
// account keys and API keys are only deleted by their owner.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	return detect.RevokeEach(ctx, tokens, p.revoke)
}

// DryRunRevoke implements detect.DryRunRevoker: the revoke endpoint has no
// rehearsal, so the token is checked the way Verify does, tokeninfo for an
// access token, and the answer says whether there is a grant to revoke.
func (p *Provider) DryRunRevoke(ctx context.Context, tok detect.Token) error {
	if !revocable(tok.Kind) {
		return errors.New(notRevocable(tok.Kind))
	}
	switch v := p.Verify(ctx, tok); v.Status {
	case detect.StatusActive:
		return nil
	case detect.StatusRevoked:
		return errors.New("already rejected by Google, nothing left to revoke")
	default:
		return errors.New(v.Detail)
	}
}

func (p *Provider) revoke(ctx context.Context, tok detect.Token) error {
	if !revocable(tok.Kind) {
		return errors.New(notRevocable(tok.Kind))
	}
	status, body, err := p.post(ctx, p.RevokeURL, url.Values{"token": {tok.Value}})
	if err != nil {
		return err
	}
	var e oauthError
	_ = json.Unmarshal(body, &e)
	switch {
	case status == http.StatusOK, status == http.StatusBadRequest && e.Error == "invalid_token":
		return nil
	}
	return errors.New(httpError(status, e))
}

func revocable(kind detect.Kind) bool {
	switch kind {
	case KindAccessToken, KindRefreshToken, KindUserCredentials:
		return true
	}
	return false
}

func notRevocable(kind detect.Kind) string {
	if kind == KindAPIKey {
		return "API keys are deleted by their owner at " + credentialsPage
	}
	return "service account keys are deleted by their owner at " + serviceAccountsPage + " or with gcloud iam service-accounts keys delete"
}
