// Package privatekey is the provider for private keys committed as PEM
// blocks: SSH keys, the keys behind TLS certificates and other PKCS#8 or
// legacy PEM material, and the encrypted signing keys cosign writes.
//
// None of them has an issuer to ask or an endpoint to revoke through. What
// makes such a leak matter is what the key opens, so the provider watches
// every scanned object for the public halves that name a key -- SSH public
// keys in authorized_keys, .pub files and Terraform or Ansible content,
// certificates, PUBLIC KEY blocks in cosign.pub and in the image policies
// that pin them -- and reports, per key, where its public half appears and
// what it protects. For SSH keys it also looks up the public keys GitHub
// publishes for the accounts that committed to the repository, so a key
// can be attributed to a login without ever being used; with --verify an
// unencrypted SSH key is offered to github.com once, which says whether
// any account or deploy key still accepts it.
//
// The key material itself is kept only for that one verification and is
// never shown, fingerprinted or written to the JSON; every key is named by
// the fingerprint of its public half, or, for encrypted material whose
// public half cannot be derived, by a hash of the block.
package privatekey

import (
	"net/http"
	"sync"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Provider implements detect.Provider, detect.CommitterCorrelator,
// detect.ProximityCorrelator and detect.PathClassifier for private keys.
type Provider struct {
	// KeysURL is where GitHub publishes the SSH public keys of an account
	// as `<login>.keys`; https://github.com/ by default.
	KeysURL string
	// MetaURL is GitHub's meta endpoint, which publishes the fingerprints of
	// its SSH host keys; https://api.github.com/meta by default. Empty
	// skips the fetch and pins the embedded fingerprints.
	MetaURL string
	// SSHAddr is the SSH endpoint --verify offers keys to; github.com:22.
	SSHAddr string
	// HostKeys are the SHA256 fingerprints of the host keys SSHAddr may
	// present; GitHub's published ones by default, replaced by what MetaURL
	// says when it can be fetched. A server with any other key is refused.
	HostKeys []string
	// Client fetches .keys files and the meta endpoint.
	Client *http.Client
	// Timeout bounds the one SSH connection --verify makes per key.
	Timeout time.Duration

	mu sync.Mutex
	// keys caches the identifiers of each login's published keys for the
	// run, so a login committed to fifty repositories is fetched once.
	keys map[string][]string
	// logins remembers which login published each identifier, for the
	// verification detail.
	logins   map[string]string
	metaOnce sync.Once
}

// New returns a Provider against GitHub.
func New() *Provider {
	return &Provider{
		KeysURL:  "https://github.com/",
		MetaURL:  "https://api.github.com/meta",
		SSHAddr:  "github.com:22",
		HostKeys: githubHostKeys,
		Client:   &http.Client{Timeout: 15 * time.Second},
		Timeout:  15 * time.Second,
		keys:     map[string][]string{},
		logins:   map[string]string{},
	}
}

// Name implements detect.Provider.
func (*Provider) Name() string { return "private key" }

const (
	// keysPage is where a GitHub account manages its SSH keys.
	keysPage = "https://github.com/settings/keys"
	// matchesLabel labels the advice line listing the files that name a
	// key's public half.
	matchesLabel = "matches"
)

// Kinds implements detect.Provider. Nothing here is revocable through an
// API; every kind carries the procedure that retires it.
func (*Provider) Kinds() []detect.KindInfo {
	return []detect.KindInfo{
		{Kind: KindSSH, Description: "SSH private key", PublicValue: true, RevokePage: keysPage,
			RevokeNote:   "a deploy key is removed under the repository's Settings → Deploy keys (the verification says which account or repository accepts the key); remove the public key from authorized_keys on every host that lists it; anyone with an unencrypted key can push, or log in, as its owner until it is removed",
			AuditNote:    "check the key's last-used date under " + keysPage + " and the account's security log for git operations since the commit date; on servers, the sshd log",
			UnlocksLabel: matchesLabel, UnlocksNone: "no public key, authorized_keys or GitHub account among the scanned material names it"},
		{Kind: KindTLS, Description: "TLS or generic PEM private key", PublicValue: true,
			RevokeNote:   "a certificate cannot be recalled from the clients that trust it: reissue it with a new key, revoke the old certificate at the CA, and rotate every Kubernetes Secret and server that holds this key",
			AuditNote:    "check the CA's issuance records and certificate transparency logs (https://crt.sh) for certificates on this key that were not requested",
			UnlocksLabel: matchesLabel, UnlocksNone: "no certificate or public key among the scanned material belongs to it"},
		{Kind: KindCosign, Description: "cosign signing key (encrypted)", PublicValue: true,
			RevokeNote:   "nothing revokes a cosign key: generate a new pair (`cosign generate-key-pair`), re-sign what matters, replace cosign.pub and every policy that pins it, or move to keyless signing; until then every signature by this key is worth what its passphrase is",
			AuditNote:    "search the Rekor transparency log for signatures by this key since the commit date (`rekor-cli search --public-key cosign.pub --pki-format x509`)",
			UnlocksLabel: matchesLabel, UnlocksNone: "no cosign.pub or image policy among the scanned material sits next to it"},
	}
}

// LocalSources implements detect.Provider: the SSH directory, cosign's
// directory, and the variables CI jobs and cosign read keys from. Only
// fingerprints are compared; a variable that holds a path or a KMS URI
// instead of a key matches nothing.
func (*Provider) LocalSources() detect.LocalSources {
	return detect.LocalSources{
		Env:       []string{"SSH_PRIVATE_KEY", "COSIGN_KEY", "COSIGN_PRIVATE_KEY"},
		HomeFiles: []string{".ssh/*", ".sigstore/*"},
	}
}
