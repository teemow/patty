package kubernetes

import (
	"encoding/json"
	"strings"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/jwt"
)

const (
	// KindClientCertificate is a client certificate with its private key,
	// as a kubeconfig embeds them; its name is the certificate's SHA-256
	// fingerprint.
	KindClientCertificate detect.Kind = "kubernetes-client-certificate"
	// KindServiceAccountToken is the JWT of a service account, legacy
	// (no expiry) or bound (expiring, tied to a pod).
	KindServiceAccountToken detect.Kind = "kubernetes-service-account-token"
	// KindToken is any other bearer token a kubeconfig user carries: a
	// static token, an OIDC id token pasted in.
	KindToken detect.Kind = "kubernetes-token"
	// KindBasicAuth is a username and password of a kubeconfig user; its
	// name is host/username.
	KindBasicAuth detect.Kind = "kubernetes-basic-auth"
	// KindSecretManifest is a Secret manifest with at least one value in
	// the clear; its name is namespace/name.
	KindSecretManifest detect.Kind = "kubernetes-secret-manifest"
)

// credential is what Token.Secret carries for this provider: the server a
// kubeconfig user belongs to, how to trust it, and the material Value does
// not hold. It is JSON so that a bare token, which has none of it, merges
// with the same token found in a kubeconfig, which has all of it.
type credential struct {
	Server   string `json:"server,omitempty"`
	CA       string `json:"ca,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	Cert     string `json:"cert,omitempty"`
	Key      string `json:"key,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func (c credential) encode() string {
	if c == (credential{}) {
		return ""
	}
	raw, _ := json.Marshal(c)
	return string(raw)
}

func decodeCredential(tok detect.Token) credential {
	var c credential
	_ = json.Unmarshal([]byte(tok.Secret), &c)
	return c
}

// Find implements detect.Provider: the users of every kubeconfig, service
// account tokens wherever they stand, and Secret manifests with plaintext
// values. A token that is both a kubeconfig user and a bare JWT in the
// same content is one finding, the kubeconfig's, which knows the server.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	seen := map[string]bool{}
	add := func(tok detect.Token) {
		key := string(tok.Kind) + ":" + tok.Value
		if !seen[key] {
			seen[key] = true
			found = append(found, tok)
		}
	}
	for _, u := range kubeconfigUsers(content) {
		if tok, ok := u.token(); ok {
			add(tok)
		}
	}
	for _, c := range jwt.Find(content) {
		if sa, ok := serviceAccountOf(c.Claims); ok {
			add(detect.Token{Kind: KindServiceAccountToken, Value: c.Value, Offset: c.Offset, Attribution: sa.String()})
		}
	}
	for _, s := range detect.Secrets(content) {
		if tok, ok := manifestToken(s); ok {
			add(tok)
		}
	}
	return found
}

// serviceAccount is what a service account token says about itself.
type serviceAccount struct {
	Namespace, Name, Pod string
	Claims               jwt.Claims
}

// serviceAccountOf classifies a token as a Kubernetes service account
// token: legacy tokens are issued by `kubernetes/serviceaccount` and name
// their account in flat claims, bound tokens carry a `kubernetes.io`
// object with the namespace, account and pod. Any other token is not
// this provider's business.
func serviceAccountOf(c jwt.Claims) (serviceAccount, bool) {
	sa := serviceAccount{Claims: c}
	if k := c.Object("kubernetes.io"); k != nil {
		sa.Namespace, _ = k["namespace"].(string)
		if acct, _ := k["serviceaccount"].(map[string]any); acct != nil {
			sa.Name, _ = acct["name"].(string)
		}
		if pod, _ := k["pod"].(map[string]any); pod != nil {
			sa.Pod, _ = pod["name"].(string)
		}
		if sa.Namespace != "" || sa.Name != "" {
			return sa, true
		}
	}
	if ns := c.String("kubernetes.io/serviceaccount/namespace"); ns != "" {
		sa.Namespace, sa.Name = ns, c.String("kubernetes.io/serviceaccount/service-account.name")
		return sa, true
	}
	if c.Issuer == "kubernetes/serviceaccount" {
		if parts := strings.Split(c.Subject, ":"); len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
			sa.Namespace, sa.Name = parts[2], parts[3]
		}
		return sa, true
	}
	return serviceAccount{}, false
}

// String is the token's attribution: whose it is and until when.
func (sa serviceAccount) String() string {
	s := "serviceaccount " + sa.Namespace + "/" + sa.Name
	if sa.Pod != "" {
		s += ", bound to pod " + sa.Pod
	}
	if sa.Claims.Expires.IsZero() {
		return s + ", no expiry (legacy token)"
	}
	return s + expiry(sa.Claims.Expires)
}

// manifestToken is the finding for a Secret manifest with values in the
// clear: named after the Secret, listing its keys and never its values.
func manifestToken(s detect.Secret) (detect.Token, bool) {
	plain := s.Plaintext()
	if s.Sops || s.Name == "" || len(plain) == 0 {
		return detect.Token{}, false
	}
	keys := make([]string, len(plain))
	for i, v := range plain {
		keys[i] = v.Key
	}
	attribution := "keys " + strings.Join(keys, ", ")
	if s.Type != "" && s.Type != "Opaque" {
		attribution = "type " + s.Type + ", " + attribution
	}
	return detect.Token{Kind: KindSecretManifest, Value: s.Ref(), Offset: s.Offset, Attribution: attribution}, true
}
