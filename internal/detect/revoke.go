package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// revokeBatch is the most credentials GitHub accepts in one revocation request.
const revokeBatch = 1000

// Revocable reports whether GitHub's credential revocation endpoint accepts
// tokens of this kind. Installation tokens (ghs_) are the exception; they
// expire within an hour anyway.
func Revocable(kind Kind) bool {
	switch kind {
	case KindPAT, KindFineGrained, KindOAuth, KindUserToServer, KindRefresh:
		return true
	}
	return false
}

// Revoker asks GitHub to revoke leaked credentials through
// POST /credentials/revoke. The endpoint is unauthenticated on purpose: it is
// meant for whoever finds a token, not only its owner, and GitHub notifies
// the owner of every revocation.
type Revoker struct {
	// BaseURL is the API root, https://api.github.com by default.
	BaseURL string
	Client  *http.Client
}

// NewRevoker returns a Revoker against the public GitHub API.
func NewRevoker() *Revoker {
	return &Revoker{BaseURL: "https://api.github.com", Client: &http.Client{Timeout: 30 * time.Second}}
}

// Revoke submits the token values for revocation, in batches the API
// accepts. GitHub processes the request asynchronously; a nil error means
// every batch was accepted, not that the tokens are already dead.
func (r *Revoker) Revoke(ctx context.Context, tokens []string) error {
	for start := 0; start < len(tokens); start += revokeBatch {
		if err := r.post(ctx, tokens[start:min(start+revokeBatch, len(tokens))]); err != nil {
			return err
		}
	}
	return nil
}

func (r *Revoker) post(ctx context.Context, tokens []string) error {
	body, err := json.Marshal(struct {
		Credentials []string `json:"credentials"`
	}{tokens})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+"/credentials/revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "patty")

	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(msg, &e) == nil && e.Message != "" {
		return fmt.Errorf("revocation refused: HTTP %d: %s", resp.StatusCode, e.Message)
	}
	return fmt.Errorf("revocation refused: HTTP %d", resp.StatusCode)
}

// RevokePage is where the owner revokes a token of this kind by hand.
func RevokePage(kind Kind) string {
	switch kind {
	case KindPAT:
		return "https://github.com/settings/tokens"
	case KindFineGrained:
		return "https://github.com/settings/personal-access-tokens"
	case KindOAuth:
		return "https://github.com/settings/applications"
	case KindUserToServer, KindRefresh:
		return "https://github.com/settings/apps/authorizations"
	case KindServerToServer:
		return "https://github.com/settings/installations"
	}
	return ""
}
