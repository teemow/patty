package azure

import (
	"context"
	"errors"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Provider by refusing: Azure has no endpoint a
// holder could revoke a client secret, a storage key or a signature at.
// The registry never gets here, no kind is revocable; the report carries
// the owner's procedures.
func (*Provider) Revoke(context.Context, []detect.Token) error {
	return errors.New("no API revokes Azure credentials by their holder; delete the secret, rotate the key or the key that signed the signature as the report says")
}
