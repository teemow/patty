package scan

import (
	"context"
	"fmt"

	"github.com/teemow/patty/internal/detect"
)

// Revocation is the outcome of asking GitHub to revoke a token.
type Revocation string

const (
	// RevocationDone means GitHub accepted the request and no longer honours the token.
	RevocationDone Revocation = "revoked"
	// RevocationPending means GitHub accepted the request but still answered
	// the follow-up check as active; revocations are processed asynchronously.
	RevocationPending Revocation = "pending"
	// RevocationUnsupported means the token family cannot be revoked through the API.
	RevocationUnsupported Revocation = "unsupported"
)

// Revocable returns the distinct active tokens across results that GitHub's
// revocation endpoint accepts, active ones first.
func Revocable(results []Result) []Finding {
	var out []Finding
	for _, f := range Merge(results) {
		if f.Active() && detect.Revocable(f.Kind) {
			out = append(out, f)
		}
	}
	return out
}

// Revoke asks GitHub to revoke the given tokens, checks each one again and
// records the outcome on every finding of that token in results. It returns
// the number of tokens GitHub confirmed dead.
func Revoke(ctx context.Context, results []Result, tokens []Finding, revoker *detect.Revoker, verifier *detect.Verifier) (int, error) {
	values := make([]string, 0, len(tokens))
	for _, f := range tokens {
		if !detect.Revocable(f.Kind) {
			return 0, fmt.Errorf("%s tokens (%s) cannot be revoked through the API", f.Kind, f.Fingerprint)
		}
		values = append(values, f.Token)
	}
	if err := revoker.Revoke(ctx, values); err != nil {
		return 0, err
	}
	done := 0
	for _, f := range tokens {
		v := verifier.Verify(ctx, detect.Token{Kind: f.Kind, Value: f.Token})
		rev := RevocationPending
		if v.Status == detect.StatusRevoked {
			rev = RevocationDone
			done++
		}
		if v.Status == detect.StatusUnknown {
			v = *f.Verification // keep what we knew rather than a transient error
		}
		record(results, f.Fingerprint, v, rev)
	}
	return done, nil
}

func record(results []Result, fingerprint string, v detect.Verification, rev Revocation) {
	for i := range results {
		for j := range results[i].Findings {
			f := &results[i].Findings[j]
			if f.Fingerprint == fingerprint {
				vv := v
				f.Verification = &vv
				f.Revocation = rev
			}
		}
	}
}
