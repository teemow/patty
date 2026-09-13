package kubernetes

import (
	"context"
	"errors"

	"github.com/teemow/patty/internal/detect"
)

// Revoke implements detect.Provider by refusing: Kubernetes has no API
// that revokes a certificate or a token. The registry never gets here, no
// kind is revocable; the report carries the procedures instead.
func (*Provider) Revoke(context.Context, []detect.Token) error {
	return errors.New("no API revokes Kubernetes credentials; rotate them as the report says")
}
