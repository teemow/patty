package sops

import (
	"context"
	"errors"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Provider by refusing: there is no one to revoke
// an identity with. The registry never gets here, no kind is revocable; the
// report carries the rotation procedure instead.
func (*Provider) Revoke(context.Context, []detect.Token) error {
	return errors.New("age identities and PGP keys cannot be revoked; rotate them as the report says")
}
