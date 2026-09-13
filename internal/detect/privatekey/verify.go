package privatekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teemow/patty/internal/detect"
)

// githubHostKeys are the fingerprints GitHub publishes for its SSH host
// keys (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints);
// the meta endpoint is asked for the current ones first.
var githubHostKeys = []string{
	"SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s", // RSA
	"SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM", // ECDSA
	"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", // Ed25519
}

// sshUser is the account every git-over-SSH host authenticates as.
const sshUser = "git"

// passphraseProtected is the verdict on encrypted material.
const passphraseProtected = "passphrase-protected; the passphrase is not in the repository unless it was committed next to it"

// errHostKey is returned by the host key callback when the server is not
// the one the fingerprints name.
var errHostKey = errors.New("host key is not GitHub's")

// Verify implements detect.Provider. An unencrypted SSH key is offered to
// the SSH endpoint once, as user git, with no command and no shell: the
// server either accepts the key, which means some account or deploy key
// still carries it, or refuses it, which means none does. The host key is
// checked against GitHub's published fingerprints first and any other
// server is refused. Encrypted keys, TLS keys and cosign keys have no one
// to ask; the matches line is their evidence.
func (p *Provider) Verify(ctx context.Context, tok detect.Token) detect.Verification {
	switch tok.Kind {
	case KindTLS:
		return unverifiable("no issuer to ask; the matches line names the certificate it belongs to when one was scanned")
	case KindCosign:
		return unverifiable(passphraseProtected + "; the matches line says where its public key is pinned")
	case KindSSH:
		if tok.Secret == "" {
			return unverifiable(passphraseProtected)
		}
		return p.verifySSH(ctx, tok)
	}
	return unknown("not a private key kind")
}

func (p *Provider) verifySSH(ctx context.Context, tok detect.Token) detect.Verification {
	signer, err := ssh.ParsePrivateKey([]byte(tok.Secret))
	if err != nil {
		return unknown("the key did not parse: " + err.Error())
	}
	hostKeys := p.hostKeys(ctx)
	host, _, _ := net.SplitHostPort(p.SSHAddr)
	if host == "" {
		host = p.SSHAddr
	}
	cfg := &ssh.ClientConfig{
		User:          sshUser,
		Auth:          []ssh.AuthMethod{ssh.PublicKeys(signer)},
		ClientVersion: "SSH-2.0-" + detect.UserAgent,
		Timeout:       p.Timeout,
		HostKeyCallback: func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			for _, want := range hostKeys {
				if fp == want {
					return nil
				}
			}
			return fmt.Errorf("%w: %s presented %s", errHostKey, hostname, fp)
		},
	}
	dialer := net.Dialer{Timeout: p.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", p.SSHAddr)
	if err != nil {
		return unknown(host + " not reachable from here: " + err.Error())
	}
	defer func() { _ = conn.Close() }()
	if p.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(p.Timeout))
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, p.SSHAddr, cfg)
	switch {
	case err == nil:
		_ = ssh.NewClient(c, chans, reqs).Close()
	case errors.Is(err, errHostKey):
		return unknown(err.Error() + "; not checked")
	case strings.Contains(err.Error(), "ssh: unable to authenticate"):
		return detect.Verification{Status: detect.StatusRevoked, Detail: host + " rejects it: on no account and no deploy key"}
	default:
		return unknown(host + " not reachable from here: " + err.Error())
	}
	detail := "accepted by " + host
	if login := p.loginOf(tok.Value); login != "" {
		detail += " as " + login + ": the key is listed on that account"
	} else if p.lookedUp() {
		detail += ": a deploy key, or the key of an account that did not commit here"
	}
	return detect.Verification{Status: detect.StatusActive, Detail: detail}
}

// lookedUp reports whether any login's keys were fetched this run.
func (p *Provider) lookedUp() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.keys) > 0
}

// hostKeys returns the fingerprints the SSH endpoint may present: what the
// meta endpoint publishes, fetched once per run, else the embedded ones.
func (p *Provider) hostKeys(ctx context.Context) []string {
	p.metaOnce.Do(func() {
		if p.MetaURL == "" || p.Client == nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.MetaURL, nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := detect.Do(p.Client, req)
		if err != nil {
			return
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return
		}
		var meta struct {
			Fingerprints map[string]string `json:"ssh_key_fingerprints"`
		}
		if json.Unmarshal(detect.ReadBody(resp.Body, 1<<20), &meta) != nil || len(meta.Fingerprints) == 0 {
			return
		}
		var keys []string
		for name, fp := range meta.Fingerprints {
			if strings.HasPrefix(name, "SHA256_") && fp != "" {
				keys = append(keys, "SHA256:"+fp)
			}
		}
		if len(keys) > 0 {
			p.mu.Lock()
			p.HostKeys = keys
			p.mu.Unlock()
		}
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.HostKeys
}

func unverifiable(detail string) detect.Verification {
	return detect.Verification{Status: detect.StatusUnverifiable, Detail: detail}
}

func unknown(detail string) detect.Verification {
	return detect.Verification{Status: detect.StatusUnknown, Detail: detail}
}
