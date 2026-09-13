// Package sops is the provider for the identities that decrypt
// sops-managed secrets: age identities and PGP private keys.
//
// Neither has an issuer to ask or a revocation endpoint. An age identity is
// valid for as long as its checksum holds, which patty verifies offline, and
// a PGP key for as long as its packets parse. What makes such a leak matter
// is what the key decrypts, so the provider also watches every scanned object
// for sops material (.sops.yaml rules and encrypted files) and reports, per
// identity, the files that list its public key or fingerprint as a
// recipient. Everything that was encrypted to a leaked recipient stays
// readable to whoever holds the key; rotation only protects what is
// encrypted from now on.
package sops

import "github.com/teemow/patty/internal/detect"

// Provider implements detect.Provider and detect.Correlator for sops.
type Provider struct{}

// New returns the sops provider.
func New() *Provider { return &Provider{} }

// Name implements detect.Provider.
func (*Provider) Name() string { return "sops" }

const (
	// unlocksLabel labels the advice line listing the files an identity decrypts.
	unlocksLabel = "decrypts"
	unlocksNone  = "no sops file in the scanned repositories lists this key as a recipient"
	// rotation is how a sops recipient is retired; there is nothing to revoke.
	rotation = "remove it from .sops.yaml, run `sops updatekeys` on every affected file, then `sops rotate -i` on each so the data key changes too"
	// past is the part of the advice that is easy to get wrong: rotation
	// does nothing for what is already committed.
	past = "Every commit already encrypted to this recipient stays decryptable by whoever holds the key, so rotation protects future commits only; rewriting history (see history below) is the only remedy for the past"
	// effect is the same warning in the form the revocation prompt uses.
	effect = "rotation protects future commits only; every commit already encrypted to this recipient stays decryptable by whoever holds the key"
)

// Kinds implements detect.Provider. Neither kind can be revoked: an
// identity is not issued by anyone, so the advice is the rotation procedure.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindAge, Description: "age identity",
			RevokeNote:   "nothing to revoke, an age identity is valid for as long as it exists; rotate instead: " + rotation + ". " + past,
			RevokeEffect: effect,
			UnlocksLabel: unlocksLabel, UnlocksNone: unlocksNone},
		{Kind: KindPGP, Description: "PGP private key",
			RevokeNote:   "nothing to revoke online; rotate instead: " + rotation + ", and publish a revocation certificate for the key (`gpg --gen-revoke`) so nobody encrypts to it again. " + past,
			RevokeEffect: effect,
			UnlocksLabel: unlocksLabel, UnlocksNone: unlocksNone},
	}
}

// LocalSources implements detect.Provider: where sops reads age identities
// from. PGP keys live in the GnuPG keyring, which is not a text file;
// `gpg --list-secret-keys` shows the fingerprints kept there.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:         []string{"SOPS_AGE_KEY"},
		EnvFiles:    []string{"SOPS_AGE_KEY_FILE"},
		ConfigFiles: []string{"sops/age/keys.txt"},
		HomeFiles:   []string{".config/sops/age/keys.txt", "Library/Application Support/sops/age/keys.txt"},
	}
}
