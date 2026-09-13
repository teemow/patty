package privatekey

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/http"
	"net/url"

	"golang.org/x/crypto/ssh"

	"github.com/teemow/patty/internal/detect"
)

// maxKeysFile bounds a .keys response; an account has at most a few
// dozen keys.
const maxKeysFile = 1 << 20

// Committers implements detect.CommitterCorrelator: the SSH public keys
// GitHub publishes for each login, under both fingerprint forms, each
// saying whose key it is. The .keys files are public and fetched without
// a token, once per login and run.
func (p *Provider) Committers(ctx context.Context, logins []string) map[string]string {
	out := map[string]string{}
	for _, login := range logins {
		for _, id := range p.publishedKeys(ctx, login) {
			if _, taken := out[id]; !taken {
				out[id] = "matches " + login + "'s GitHub SSH key"
			}
		}
	}
	return out
}

// loginOf returns the login that published a key with this identifier,
// among the logins looked up so far, or "".
func (p *Provider) loginOf(id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logins[id]
}

func (p *Provider) publishedKeys(ctx context.Context, login string) []string {
	if !validLogin(login) {
		return nil
	}
	p.mu.Lock()
	if p.keys == nil {
		p.keys, p.logins = map[string][]string{}, map[string]string{}
	}
	ids, ok := p.keys[login]
	p.mu.Unlock()
	if ok {
		return ids
	}
	ids = p.fetchKeys(ctx, login)
	p.mu.Lock()
	p.keys[login] = ids
	for _, id := range ids {
		if _, taken := p.logins[id]; !taken {
			p.logins[id] = login
		}
	}
	p.mu.Unlock()
	return ids
}

// fetchKeys reads https://github.com/<login>.keys: one authorized_keys
// line per key. Anything but a 200 means no keys are known.
func (p *Provider) fetchKeys(ctx context.Context, login string) []string {
	if p.Client == nil || p.KeysURL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.KeysURL+url.PathEscape(login)+".keys", nil)
	if err != nil {
		return nil
	}
	resp, err := detect.Do(p.Client, req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var ids []string
	for line := range bytes.Lines(detect.ReadBody(resp.Body, maxKeysFile)) {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey(line); err == nil {
			ids = append(ids, Identifiers(pub)...)
		}
	}
	return ids
}

// Identifiers returns the fingerprint forms a private key matching this
// public key is named by: the OpenSSH fingerprint and, for algorithms
// with a PKIX form, the SubjectPublicKeyInfo hash.
func Identifiers(pub ssh.PublicKey) []string {
	ids := []string{ssh.FingerprintSHA256(pub)}
	if c, ok := pub.(ssh.CryptoPublicKey); ok {
		if spki, err := x509.MarshalPKIXPublicKey(c.CryptoPublicKey()); err == nil {
			ids = append(ids, spkiHash(spki))
		}
	}
	return ids
}

// validLogin is the shape of a GitHub login: up to 39 alphanumerics and
// hyphens. Anything else is not looked up.
func validLogin(login string) bool {
	if login == "" || len(login) > 39 {
		return false
	}
	for i := range len(login) {
		if c := login[i]; !detect.IsAlnum(c) && c != '-' {
			return false
		}
	}
	return true
}
