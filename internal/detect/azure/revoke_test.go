package azure

import (
	"context"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestRevoke(t *testing.T) {
	p := provider()
	if err := p.Revoke(context.Background(), []detect.Token{{Kind: KindClientSecret, Value: clientSecret("Ab1")}}); err == nil {
		t.Error("nothing here is revocable by the holder")
	}
	for _, k := range p.Kinds() {
		if k.Revocable {
			t.Errorf("%s is marked revocable", k.Kind)
		}
		if k.RevokeNote == "" || k.AuditNote == "" {
			t.Errorf("%s carries no procedure", k.Kind)
		}
	}
	if _, ok := any(p).(detect.DryRunRevoker); ok {
		t.Error("no revocation, no dry run")
	}
}
