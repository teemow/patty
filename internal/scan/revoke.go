package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/teemow/patty/internal/detect"
)

// Revocation is the outcome of asking a provider to revoke a credential.
type Revocation string

const (
	// RevocationDone means the provider accepted the request and no longer honours the credential.
	RevocationDone Revocation = "revoked"
	// RevocationPending means the provider accepted the request but still
	// answered the follow-up check as active; GitHub processes revocations
	// asynchronously.
	RevocationPending Revocation = "pending"
	// RevocationUnsupported means the credential family cannot be revoked through the API.
	RevocationUnsupported Revocation = "unsupported"
)

// Revocable returns the distinct active credentials across results that
// their provider's revocation endpoint accepts, active ones first.
func Revocable(results []Result, registry *detect.Registry) []Finding {
	var out []Finding
	for _, f := range Merge(results) {
		if f.Active() && registry.Revocable(f.Kind) {
			out = append(out, f)
		}
	}
	return out
}

// Revoke asks each credential's provider to revoke it, checks each one
// again and records the outcome on every finding of that credential in
// results. It returns the number of credentials the providers confirmed
// dead. A provider that refuses is reported in the error; the other
// providers' credentials are still revoked and checked.
func Revoke(ctx context.Context, results []Result, tokens []Finding, registry *detect.Registry) (int, error) {
	byProvider := map[detect.Provider][]Finding{}
	var order []detect.Provider
	for _, f := range tokens {
		p := registry.Provider(f.Kind)
		if p == nil || !registry.Revocable(f.Kind) {
			return 0, fmt.Errorf("%s credentials (%s) cannot be revoked through the API", f.Kind, f.Fingerprint)
		}
		if _, seen := byProvider[p]; !seen {
			order = append(order, p)
		}
		byProvider[p] = append(byProvider[p], f)
	}
	done := 0
	var errs []error
	for _, p := range order {
		group := byProvider[p]
		tokens := make([]detect.Token, len(group))
		for i, f := range group {
			tokens[i] = f.Detected()
		}
		if err := p.Revoke(ctx, tokens); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name(), err))
			continue
		}
		for _, f := range group {
			v := p.Verify(ctx, f.Detected())
			rev := RevocationPending
			if v.Status == detect.StatusRevoked {
				rev = RevocationDone
				done++
			}
			if v.Status == detect.StatusUnknown && f.Verification != nil {
				v = *f.Verification // keep what we knew rather than a transient error
			}
			record(results, f.Fingerprint, v, rev)
		}
	}
	return done, errors.Join(errs...)
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
