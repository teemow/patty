package azure

import (
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestNotRevocable(t *testing.T) {
	p := provider()
	if _, ok := any(p).(detect.Revoker); ok {
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
