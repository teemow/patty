package sops

import (
	"context"

	"github.com/teemow/patty/internal/detect"
)

// Verify implements detect.Provider without contacting anything: an
// identity has no issuer to ask. It is valid by construction, the checksum
// or the packet structure said so when it was found, and whether it matters
// is what the decrypts line answers.
func (*Provider) Verify(_ context.Context, tok detect.Token) detect.Verification {
	proof := "the checksum holds"
	if tok.Kind == KindPGP {
		proof = "the key parses"
	}
	return detect.Verification{Status: detect.StatusUnverifiable, Detail: "no issuer to ask: valid by construction (" + proof + "); what it opens is listed under decrypts"}
}
