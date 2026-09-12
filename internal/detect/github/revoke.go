package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/teemow/patty/internal/detect"
)

// revokeBatch is the most credentials GitHub accepts in one revocation request.
const revokeBatch = 1000

// Revoke implements detect.Provider through POST /credentials/revoke. The
// endpoint is unauthenticated on purpose: it is meant for whoever finds a
// token, not only its owner, and GitHub notifies the owner of every
// revocation. Tokens are submitted in batches the API accepts; GitHub
// processes them asynchronously, so a nil error means every batch was
// accepted, not that the tokens are already dead.
func (p *Provider) Revoke(ctx context.Context, tokens []detect.Token) error {
	values := make([]string, len(tokens))
	for i, tok := range tokens {
		values[i] = tok.Value
	}
	for start := 0; start < len(values); start += revokeBatch {
		if err := p.post(ctx, values[start:min(start+revokeBatch, len(values))]); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) post(ctx context.Context, tokens []string) error {
	body, err := json.Marshal(struct {
		Credentials []string `json:"credentials"`
	}{tokens})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/credentials/revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(detect.ReadBody(resp.Body, 4096), &e) == nil && e.Message != "" {
		return fmt.Errorf("revocation refused: HTTP %d: %s", resp.StatusCode, e.Message)
	}
	return fmt.Errorf("revocation refused: HTTP %d", resp.StatusCode)
}
