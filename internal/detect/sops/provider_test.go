package sops

import (
	"context"
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

func TestKindsAndLocalSources(t *testing.T) {
	p := New()
	if p.Name() != "sops" {
		t.Fatalf("name %q", p.Name())
	}
	var _ detect.Correlator = p
	for _, k := range p.Kinds() {
		if k.Revocable || k.RevokePage != "" {
			t.Errorf("%s: nothing can revoke an identity, got %+v", k.Kind, k)
		}
		for _, want := range []string{"sops updatekeys", "sops rotate -i", "rotation protects future commits only", "rewriting history"} {
			if !strings.Contains(k.RevokeNote, want) {
				t.Errorf("%s: revoke note lacks %q: %s", k.Kind, want, k.RevokeNote)
			}
		}
		if k.UnlocksLabel != "decrypts" || !strings.Contains(k.UnlocksNone, "no sops file") {
			t.Errorf("%s: unlocks advice %+v", k.Kind, k)
		}
	}
	if k := p.Kinds()[1]; k.Kind != KindPGP || !strings.Contains(k.RevokeNote, "revocation certificate") {
		t.Fatalf("PGP advice must mention the revocation certificate: %+v", k)
	}
	src := p.LocalSources()
	if len(src.Env) != 1 || src.Env[0] != "SOPS_AGE_KEY" || len(src.EnvFiles) != 1 || src.EnvFiles[0] != "SOPS_AGE_KEY_FILE" || src.ConfigFiles[0] != "sops/age/keys.txt" {
		t.Fatalf("local sources %+v", src)
	}
	for _, f := range append(src.ConfigFiles, src.HomeFiles...) {
		if strings.Contains(f, ".gnupg") {
			t.Fatal("the GnuPG keyring is not a text file and must not be read")
		}
	}
}

func TestVerifyAndRevokeContactNothing(t *testing.T) {
	p := New()
	for _, kind := range []detect.Kind{KindAge, KindPGP} {
		v := p.Verify(context.Background(), detect.Token{Kind: kind, Value: "x"})
		if v.Status != detect.StatusUnverifiable || !strings.Contains(v.Detail, "valid by construction") || !strings.Contains(v.Detail, "decrypts") {
			t.Fatalf("%s: %+v", kind, v)
		}
	}
	if err := p.Revoke(context.Background(), []detect.Token{{Kind: KindAge}}); err == nil || !strings.Contains(err.Error(), "cannot be revoked") {
		t.Fatalf("revoke: %v", err)
	}
}
