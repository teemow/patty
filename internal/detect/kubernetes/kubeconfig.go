package kubernetes

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/detect/jwt"
)

// cluster is the server a kubeconfig user talks to and how to trust it.
type cluster struct {
	Server   string `yaml:"server"`
	CAData   string `yaml:"certificate-authority-data"`
	Insecure bool   `yaml:"insecure-skip-tls-verify"`
}

// userConfig is the credential part of a kubeconfig user. The fields that
// name files or plugins (client-certificate, client-key, tokenFile, exec,
// auth-provider) hold no secret and are not read.
type userConfig struct {
	CertData string `yaml:"client-certificate-data"`
	KeyData  string `yaml:"client-key-data"`
	Token    string `yaml:"token"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// user is one kubeconfig user with the cluster its contexts point at.
type user struct {
	Name    string
	Offset  int
	Config  userConfig
	Cluster cluster
}

// kubeconfigUsers returns the users of every kubeconfig in content, each
// resolved to its cluster through the contexts. Content that does not
// spell `kind: Config` next to a users list costs two substring searches.
func kubeconfigUsers(content []byte) []user {
	if !detect.HasKind(content, "Config") || !bytes.Contains(content, []byte("users")) {
		return nil
	}
	var users []user
	for _, doc := range detect.Documents(content) {
		root, ok := doc.Parse()
		if !ok || detect.Scalar(root, "kind") != "Config" {
			continue
		}
		clusters := map[string]cluster{}
		for _, n := range sequence(root, "clusters") {
			var c cluster
			if cn := detect.Child(n, "cluster"); cn != nil && cn.Decode(&c) == nil {
				clusters[detect.Scalar(n, "name")] = c
			}
		}
		clusterOf := map[string]string{} // user -> cluster, first context wins
		for _, n := range sequence(root, "contexts") {
			if ctx := detect.Child(n, "context"); ctx != nil {
				if u := detect.Scalar(ctx, "user"); u != "" {
					if _, seen := clusterOf[u]; !seen {
						clusterOf[u] = detect.Scalar(ctx, "cluster")
					}
				}
			}
		}
		for _, n := range sequence(root, "users") {
			u := user{Name: detect.Scalar(n, "name"), Offset: doc.Offset(n)}
			if un := detect.Child(n, "user"); un == nil || un.Decode(&u.Config) != nil {
				continue
			}
			u.Cluster = clusters[clusterOf[u.Name]]
			users = append(users, u)
		}
	}
	return users
}

func sequence(root *yaml.Node, key string) []*yaml.Node {
	if n := detect.Child(root, key); n != nil && n.Kind == yaml.SequenceNode {
		return n.Content
	}
	return nil
}

// token turns the user into its finding, if it carries a secret: a
// certificate with its key, a token, or a login.
func (u user) token() (detect.Token, bool) {
	cred := credential{Server: u.Cluster.Server, Insecure: u.Cluster.Insecure}
	if ca, err := base64.StdEncoding.DecodeString(strings.TrimSpace(u.Cluster.CAData)); err == nil {
		cred.CA = string(ca)
	}
	server := ""
	if cred.Server != "" {
		server = ", server " + cred.Server
	}
	switch {
	case u.Config.CertData != "" && u.Config.KeyData != "":
		cert, ok := parseCertificate(u.Config.CertData, u.Config.KeyData)
		if !ok {
			return detect.Token{}, false
		}
		cred.Cert, cred.Key = cert.PEM, cert.KeyPEM
		return detect.Token{Kind: KindClientCertificate, Value: cert.Fingerprint, Offset: u.Offset, ChecksumVerified: true,
			Attribution: cert.String() + server, Secret: cred.encode()}, true
	case u.Config.Token != "":
		tok := detect.Token{Kind: KindToken, Value: u.Config.Token, Offset: u.Offset, Secret: cred.encode(), Attribution: "bearer token"}
		if claims, ok := jwt.Decode(u.Config.Token); ok {
			if sa, ok := serviceAccountOf(claims); ok {
				tok.Kind, tok.Attribution = KindServiceAccountToken, sa.String()
			} else if claims.Issuer != "" {
				tok.Attribution = "JWT issued by " + claims.Issuer + expiry(claims.Expires)
			}
		}
		tok.Attribution += server
		return tok, true
	case u.Config.Username != "" && u.Config.Password != "":
		cred.Username, cred.Password = u.Config.Username, u.Config.Password
		value := u.Config.Username
		if host := hostOf(cred.Server); host != "" {
			value = host + "/" + value
		}
		return detect.Token{Kind: KindBasicAuth, Value: value, Offset: u.Offset, Secret: cred.encode(), Attribution: "user " + u.Config.Username + server}, true
	}
	return detect.Token{}, false
}

func hostOf(server string) string {
	if u, err := url.Parse(server); err == nil {
		return u.Host
	}
	return ""
}

// expiry renders an expiry for an attribution: ", expires 2027-01-31" or
// ", expired 2025-01-31"; "" when there is none.
func expiry(t time.Time) string {
	switch {
	case t.IsZero():
		return ""
	case t.Before(time.Now()):
		return ", expired " + day(t)
	}
	return ", expires " + day(t)
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }
