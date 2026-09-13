package privatekey

import (
	"context"
	"crypto"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/teemow/patty/internal/detect"
)

// sshServer runs an SSH server that accepts exactly one public key, as
// GitHub does for a key on some account, and returns its address and the
// fingerprint of its host key.
func sshServer(t *testing.T, accepted crypto.PublicKey) (addr, hostKey string) {
	t.Helper()
	acceptedPub, err := ssh.NewPublicKey(accepted)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519Key(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(acceptedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no shell")
				}
				_ = sc.Close()
			}()
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func provider(addr string, hostKeys ...string) *Provider {
	p := New()
	p.SSHAddr, p.HostKeys, p.MetaURL, p.Timeout = addr, hostKeys, "", 5*time.Second
	return p
}

func TestVerifySSHKey(t *testing.T) {
	accepted, rejected := ed25519Key(t), ecdsaKey(t)
	addr, hostKey := sshServer(t, accepted.Public())
	ctx := context.Background()

	p := provider(addr, "SHA256:something-else", hostKey)
	v := p.Verify(ctx, one(t, openssh(t, accepted, "", "")))
	if v.Status != detect.StatusActive || v.Detail != "accepted by 127.0.0.1" {
		t.Fatalf("accepted key: %+v", v)
	}
	v = p.Verify(ctx, one(t, openssh(t, rejected, "", "")))
	if v.Status != detect.StatusRevoked || v.Detail != "127.0.0.1 rejects it: on no account and no deploy key" {
		t.Fatalf("rejected key: %+v", v)
	}
	// A PKCS#1 key reclassified as an SSH key verifies the same way.
	tok := one(t, pkcs1(rsaKey(t)))
	tok.Kind = KindSSH
	if v := p.Verify(ctx, tok); v.Status != detect.StatusRevoked {
		t.Fatalf("pem ssh key: %+v", v)
	}

	// The wrong host key is refused before any key is offered.
	v = provider(addr, "SHA256:not-this-server").Verify(ctx, one(t, openssh(t, accepted, "", "")))
	if v.Status != detect.StatusUnknown || !strings.Contains(v.Detail, "host key is not GitHub's") || !strings.Contains(v.Detail, hostKey) {
		t.Fatalf("host key: %+v", v)
	}

	// Nobody listening is not a verdict.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := closed.Addr().String()
	_ = closed.Close()
	if v := provider(dead, hostKey).Verify(ctx, one(t, openssh(t, accepted, "", ""))); v.Status != detect.StatusUnknown || !strings.Contains(v.Detail, "not reachable") {
		t.Fatalf("unreachable: %+v", v)
	}
}

func TestVerifyNamesTheLoginThatPublishedTheKey(t *testing.T) {
	accepted := ed25519Key(t)
	addr, hostKey := sshServer(t, accepted.Public())
	srv, _ := keysServer(t, map[string]string{"/octocat.keys": authorizedLine(t, accepted.Public(), "") + "\n"})
	p := provider(addr, hostKey)
	p.KeysURL, p.Client = srv.URL+"/", srv.Client()
	ctx := context.Background()
	p.Committers(ctx, []string{"octocat"})
	if v := p.Verify(ctx, one(t, openssh(t, accepted, "", ""))); v.Status != detect.StatusActive || v.Detail != "accepted by 127.0.0.1 as octocat: the key is listed on that account" {
		t.Fatalf("%+v", v)
	}
	other := ed25519Key(t)
	otherAddr, otherHost := sshServer(t, other.Public())
	p.SSHAddr, p.HostKeys = otherAddr, []string{otherHost}
	if v := p.Verify(ctx, one(t, openssh(t, other, "", ""))); v.Status != detect.StatusActive || v.Detail != "accepted by 127.0.0.1: a deploy key, or the key of an account that did not commit here" {
		t.Fatalf("%+v", v)
	}
}

func TestVerifyFetchesHostKeysFromMeta(t *testing.T) {
	accepted := ed25519Key(t)
	addr, hostKey := sshServer(t, accepted.Public())
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/meta" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ssh_key_fingerprints": map[string]string{"SHA256_ED25519": strings.TrimPrefix(hostKey, "SHA256:"), "SHA256_RSA": "unused"}})
	}))
	t.Cleanup(meta.Close)
	p := provider(addr, "SHA256:stale-embedded-value")
	p.MetaURL, p.Client = meta.URL+"/meta", meta.Client()
	if v := p.Verify(context.Background(), one(t, openssh(t, accepted, "", ""))); v.Status != detect.StatusActive {
		t.Fatalf("%+v", v)
	}
	if keys := p.hostKeys(context.Background()); len(keys) != 2 {
		t.Fatalf("host keys %v", keys)
	}
	// An unreachable meta endpoint keeps the embedded fingerprints.
	q := provider(addr, hostKey)
	q.MetaURL, q.Client = "http://127.0.0.1:1/meta", &http.Client{Timeout: time.Second}
	if keys := q.hostKeys(context.Background()); len(keys) != 1 || keys[0] != hostKey {
		t.Fatalf("fallback host keys %v", keys)
	}
	if New().HostKeys[0] != githubHostKeys[0] {
		t.Fatal("the default provider pins GitHub's published fingerprints")
	}
}

func TestVerifyUnverifiableKinds(t *testing.T) {
	p := provider("127.0.0.1:1")
	ctx := context.Background()
	cases := map[string]detect.Token{
		"encrypted ssh": one(t, openssh(t, ed25519Key(t), "", "pw")),
		"tls":           one(t, pkcs8(t, ecdsaKey(t))),
		"cosign":        one(t, cosignKey(t)),
	}
	for name, tok := range cases {
		if v := p.Verify(ctx, tok); v.Status != detect.StatusUnverifiable || v.Detail == "" {
			t.Errorf("%s: %+v", name, v)
		}
	}
	if v := p.Verify(ctx, detect.Token{Kind: "github-pat"}); v.Status != detect.StatusUnknown {
		t.Fatalf("foreign kind: %+v", v)
	}
	if v := p.Verify(ctx, detect.Token{Kind: KindSSH, Secret: "not a key"}); v.Status != detect.StatusUnknown {
		t.Fatalf("unparseable: %+v", v)
	}
}
