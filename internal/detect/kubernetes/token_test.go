package kubernetes

import (
	"strings"
	"testing"
	"time"

	"github.com/teemow/patty/internal/detect"
)

type detectToken = detect.Token

const server = "https://k8s.example.com:6443"

var find = New().Find

func TestKindsAndLocalSources(t *testing.T) {
	p := New()
	if p.Name() != "Kubernetes" {
		t.Fatalf("name %q", p.Name())
	}
	var _ detect.ServerVerifier = p
	kinds := map[detect.Kind]detect.KindInfo{}
	for _, k := range p.Kinds() {
		if k.Revocable || k.RevokePage != "" || k.RevokeNote == "" || k.AuditNote == "" {
			t.Errorf("%s: nothing can be revoked through an API, every kind needs a procedure and an audit hint: %+v", k.Kind, k)
		}
		kinds[k.Kind] = k
	}
	if !strings.Contains(kinds[KindClientCertificate].RevokeNote, "no certificate revocation") || !strings.Contains(kinds[KindClientCertificate].RevokeNote, "CA") {
		t.Errorf("certificate advice: %s", kinds[KindClientCertificate].RevokeNote)
	}
	if !strings.Contains(kinds[KindServiceAccountToken].RevokeNote, "kubectl delete secret") || !strings.Contains(kinds[KindServiceAccountToken].RevokeNote, "ServiceAccount") {
		t.Errorf("service account advice: %s", kinds[KindServiceAccountToken].RevokeNote)
	}
	if !strings.Contains(kinds[KindBasicAuth].RevokeNote, "basic-auth file") {
		t.Errorf("basic auth advice: %s", kinds[KindBasicAuth].RevokeNote)
	}
	if m := kinds[KindSecretManifest]; !m.Opaque || !m.PublicValue || !strings.Contains(m.RevokeNote, "sops") || !strings.Contains(m.RevokeNote, "--ignore "+string(KindSecretManifest)) {
		t.Errorf("secret manifest kind: %+v", m)
	}
	src := p.LocalSources()
	if len(src.EnvFiles) != 1 || src.EnvFiles[0] != "KUBECONFIG" || src.HomeFiles[0] != ".kube/config" || src.ConfigFiles[0] != "kube/config" || len(src.Env) != 0 || len(src.Commands) != 0 {
		t.Fatalf("local sources %+v", src)
	}
}

func TestFindKubeconfigUsers(t *testing.T) {
	ca := newAuthority(t, "kubernetes")
	certPEM, keyPEM := ca.client(t, "kubernetes-admin", []string{"system:masters", "kubeadm:cluster-admins"}, time.Date(2031, 3, 4, 0, 0, 0, 0, time.UTC))
	oldPEM, oldKey := ca.client(t, "old-admin", nil, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	_, wrongKey := ca.client(t, "other", nil, time.Now().Add(time.Hour))
	sa := legacyToken(t, "kube-system", "deployer")
	oidc := mintJWT(t, map[string]any{"iss": "https://login.example.com", "sub": "jane", "exp": time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC).Unix()})
	static := "static-bearer-token-value-0123456789"
	content := kubeconfig(server, ca.PEM, false,
		certUser("admin", certPEM, keyPEM),
		certUser("old", oldPEM, oldKey),
		certUser("mismatch", certPEM, wrongKey),
		tokenUser("sa", sa),
		tokenUser("oidc", oidc),
		tokenUser("static", static),
		basicUser("basic", "jane", "hunter2-hunter2"),
		execUser("eks"),
	)
	got := find([]byte(content))
	if len(got) != 6 {
		t.Fatalf("want admin, old, sa, oidc, static and basic, got %d: %+v", len(got), redactAll(got))
	}
	byValue := map[string]detectToken{}
	for _, tok := range got {
		byValue[tok.Value] = tok
	}
	var admin, old detectToken
	for _, tok := range got {
		if tok.Kind == KindClientCertificate && strings.Contains(tok.Attribution, "CN=kubernetes-admin") {
			admin = tok
		}
		if tok.Kind == KindClientCertificate && strings.Contains(tok.Attribution, "CN=old-admin") {
			old = tok
		}
	}
	if admin.Attribution != "CN=kubernetes-admin groups=system:masters,kubeadm:cluster-admins issuer kubernetes, expires 2031-03-04, server "+server || !admin.ChecksumVerified || len(admin.Value) != 64 {
		t.Fatalf("admin: %+v", redact(admin))
	}
	cred := decodeCredential(admin)
	if cred.Server != server || cred.CA != string(ca.PEM) || cred.Cert != string(certPEM) || cred.Key != string(keyPEM) || cred.Insecure {
		t.Fatalf("admin credential lacks the material --verify needs: %+v", cred)
	}
	if !strings.Contains(old.Attribution, ", expired 2024-01-01, server ") || old.Value == admin.Value {
		t.Fatalf("old: %+v", redact(old))
	}
	if tok := byValue[sa]; tok.Kind != KindServiceAccountToken || tok.Attribution != "serviceaccount kube-system/deployer, no expiry (legacy token), server "+server || decodeCredential(tok).Server != server {
		t.Fatalf("sa: %+v", redact(tok))
	}
	if tok := byValue[oidc]; tok.Kind != KindToken || tok.Attribution != "JWT issued by https://login.example.com, expires 2031-01-01, server "+server {
		t.Fatalf("oidc: %+v", redact(tok))
	}
	if tok := byValue[static]; tok.Kind != KindToken || tok.Attribution != "bearer token, server "+server {
		t.Fatalf("static: %+v", redact(tok))
	}
	if tok := byValue["k8s.example.com:6443/jane"]; tok.Kind != KindBasicAuth || tok.Attribution != "user jane, server "+server || decodeCredential(tok).Password != "hunter2-hunter2" || decodeCredential(tok).Username != "jane" {
		t.Fatalf("basic: %+v", redact(tok))
	}
	for _, tok := range got {
		if strings.Contains(tok.Attribution, string(keyPEM[30:60])) || strings.Contains(tok.Attribution, "hunter2") || strings.Contains(tok.Value, "PRIVATE") {
			t.Fatalf("secret material in a printable field: %+v", redact(tok))
		}
		if !strings.HasPrefix(content[tok.Offset:], "name: ") {
			t.Errorf("offset %d points at %q, not at the user", tok.Offset, content[tok.Offset:tok.Offset+8])
		}
	}
}

func TestFindKubeconfigWithoutContextHasNoServer(t *testing.T) {
	content := strings.Replace(kubeconfig(server, nil, true, tokenUser("t", "some-token-value-0123456789")), "    user: t\n", "    user: someone-else\n", 1)
	got := find([]byte(content))
	if len(got) != 1 || got[0].Kind != KindToken || got[0].Attribution != "bearer token" || got[0].Secret != "" {
		t.Fatalf("user without a context: %+v", redactAll(got))
	}
	for _, content := range []string{
		"apiVersion: v1\nkind: Config\nusers: []\n",
		"kind: ConfigMap\nusers:\n- name: x\n  user:\n    token: abc\n",
		"users:\n- name: x\n  user:\n    token: abc\n",
		"apiVersion: v1\nkind: Config\nusers:\n- name: x\n  user:\n    client-certificate-data: not-base64!\n    client-key-data: nope\n",
	} {
		if got := find([]byte(content)); got != nil {
			t.Errorf("%q: %+v", content, redactAll(got))
		}
	}
}

func TestFindServiceAccountTokensAnywhere(t *testing.T) {
	legacy := legacyToken(t, "default", "builder")
	bound := boundToken(t, "apps", "worker", "worker-7f9c", time.Date(2031, 6, 1, 12, 0, 0, 0, time.UTC))
	expired := boundToken(t, "apps", "worker", "worker-old", time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC))
	oidc := mintJWT(t, map[string]any{"iss": "https://accounts.example.com", "sub": "someone", "aud": "app"})
	content := "TOKEN=" + legacy + "\nkubectl --token=" + bound + " get pods\nold: " + expired + "\nid_token: " + oidc + "\nagain " + legacy + "\n"
	got := find([]byte(content))
	if len(got) != 3 {
		t.Fatalf("want the legacy token once, the bound and the expired one, got %d: %+v", len(got), redactAll(got))
	}
	byValue := map[string]detectToken{}
	for _, tok := range got {
		byValue[tok.Value] = tok
		if tok.Kind != KindServiceAccountToken || tok.Secret != "" || tok.ChecksumVerified {
			t.Errorf("bare token: %+v", redact(tok))
		}
	}
	if tok := byValue[legacy]; tok.Attribution != "serviceaccount default/builder, no expiry (legacy token)" || tok.Offset != len("TOKEN=") {
		t.Fatalf("legacy: %+v", redact(tok))
	}
	if tok := byValue[bound]; tok.Attribution != "serviceaccount apps/worker, bound to pod worker-7f9c, expires 2031-06-01" {
		t.Fatalf("bound: %+v", redact(tok))
	}
	if tok := byValue[expired]; tok.Attribution != "serviceaccount apps/worker, bound to pod worker-old, expired 2024-06-01" {
		t.Fatalf("expired: %+v", redact(tok))
	}
	if _, ok := byValue[oidc]; ok {
		t.Fatal("a JWT of another issuer is not this provider's finding")
	}
}

func TestFindSecretManifests(t *testing.T) {
	plain := manifest("prod", "db", map[string]string{"password": "s3cr3t-value", "username": "app"}, nil, "type: Opaque\n")
	tls := manifest("", "ingress-tls", map[string]string{"tls.crt": "cert", "tls.key": "key"}, nil, "type: kubernetes.io/tls\n")
	sops := manifest("prod", "enc", nil, map[string]string{"password": "ENC[AES256_GCM,data:xyz,iv:abc,tag:def,type:str]"}, "sops:\n  version: 3.8.1\n")
	templated := manifest("prod", "tpl", nil, map[string]string{"password": `"{{ .Values.password }}"`, "url": `"${DATABASE_URL}"`, "empty": `""`}, "")
	got := find([]byte(plain + "---\n" + tls + "---\n" + sops + "---\n" + templated))
	if len(got) != 2 {
		t.Fatalf("want the plain and the tls Secret only, got %+v", got)
	}
	if got[0].Kind != KindSecretManifest || got[0].Value != "prod/db" || got[0].Attribution != "keys password, username" && got[0].Attribution != "keys username, password" || got[0].ChecksumVerified || got[0].Secret != "" {
		t.Fatalf("plain: %+v", got[0])
	}
	if got[1].Value != "ingress-tls" || !strings.HasPrefix(got[1].Attribution, "type kubernetes.io/tls, keys tls.") {
		t.Fatalf("tls: %+v", got[1])
	}
	for _, tok := range got {
		if strings.Contains(tok.Attribution, "s3cr3t") || strings.Contains(tok.Attribution, "cert") && !strings.Contains(tok.Attribution, "tls.crt") {
			t.Fatalf("a value leaked into the attribution: %+v", tok)
		}
	}
	if got := find([]byte(manifest("", "", map[string]string{"k": "v"}, nil, ""))); got != nil {
		t.Fatalf("a Secret without a name is not a finding: %+v", got)
	}
}

func TestNotRevocable(t *testing.T) {
	if _, ok := any(New()).(detect.Revoker); ok {
		t.Fatal("no API revokes Kubernetes credentials")
	}
}

// redact keeps test failures free of PEM and token material.
func redact(tok detectToken) detectToken {
	tok.Secret = detect.Redact(tok.Secret)
	tok.Value = detect.Redact(tok.Value)
	return tok
}

func redactAll(toks []detectToken) []detectToken {
	out := make([]detectToken, len(toks))
	for i, tok := range toks {
		out[i] = redact(tok)
	}
	return out
}
