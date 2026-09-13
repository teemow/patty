package gitlab

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindPAT is a personal, project or group access token (glpat-).
	KindPAT detect.Kind = "gitlab-pat"
	// KindDeployToken is a deploy token (gldt-).
	KindDeployToken detect.Kind = "gitlab-deploy-token"
	// KindRunnerToken is a runner authentication token (glrt-).
	KindRunnerToken detect.Kind = "gitlab-runner-token"
	// KindJobToken is a CI job token (glcbt-).
	KindJobToken detect.Kind = "gitlab-ci-job-token"
	// KindTriggerToken is a pipeline trigger token (glptt-).
	KindTriggerToken detect.Kind = "gitlab-pipeline-trigger-token"
	// KindFeedToken is a user's feed token (glft-).
	KindFeedToken detect.Kind = "gitlab-feed-token"
	// KindIncomingMailToken is a user's incoming email token (glimt-).
	KindIncomingMailToken detect.Kind = "gitlab-incoming-mail-token"
	// KindAgentToken is an agent for Kubernetes token (glagent-).
	KindAgentToken detect.Kind = "gitlab-agent-token"
	// KindOAuthAppSecret is an OAuth application secret (gloas-).
	KindOAuthAppSecret detect.Kind = "gitlab-oauth-app-secret"
	// KindFeatureFlagClientToken is a feature flag client token (glffct-).
	KindFeatureFlagClientToken detect.Kind = "gitlab-feature-flag-client-token"
	// KindSCIMToken is a group's SCIM token (glsoat-).
	KindSCIMToken detect.Kind = "gitlab-scim-token"
)

// stem is what every prefix starts with; one substring pass finds them all.
const stem = "gl"

// family is one token format: its prefix and the fixed length of its body
// in the token alphabet; 0 for a family with a shape of its own.
type family struct {
	prefix string
	kind   detect.Kind
	body   int
}

// families lists the prefixes after the stem, longest first so that a
// prefix is never mistaken for a shorter one it starts with.
var families = []family{
	{"agent-", KindAgentToken, 50},
	{"ffct-", KindFeatureFlagClientToken, 20},
	{"soat-", KindSCIMToken, 20},
	{"cbt-", KindJobToken, 0},
	{"imt-", KindIncomingMailToken, 25},
	{"ptt-", KindTriggerToken, 0},
	{"oas-", KindOAuthAppSecret, 64},
	{"pat-", KindPAT, 20},
	{"dt-", KindDeployToken, 20},
	{"rt-", KindRunnerToken, 20},
	{"ft-", KindFeedToken, 20},
}

const (
	triggerLen       = 40 // hex
	jobPartitionMin  = 1
	jobPartitionMax  = 5
	deployUserPrefix = "gitlab+deploy-token-"
)

// companion is what Token.Secret carries: the username a deploy token was
// found next to, and the instances Bind recorded. JSON so that the two
// merge whatever order they arrive in.
type companion struct {
	Username  string   `json:"username,omitempty"`
	Instances []string `json:"instances,omitempty"`
}

func (c companion) encode() string {
	if c.Username == "" && len(c.Instances) == 0 {
		return ""
	}
	raw, _ := json.Marshal(c)
	return string(raw)
}

func decode(tok detect.Token) companion {
	var c companion
	_ = json.Unmarshal([]byte(tok.Secret), &c)
	return c
}

// Find implements detect.Provider. One substring pass for the shared `gl`
// stem, then the family's exact shape at each candidate: the routable
// layout with its checksum for personal access and runner tokens, a fixed
// body in the token alphabet for most families, forty hex characters for
// a trigger token, a partition and a body for a job token. A deploy token
// is paired with the deploy username written in the same object.
func (*Provider) Find(content []byte) []detect.Token {
	found := detect.ScanPrefix(nil, content, stem, func(start int) (detect.Token, bool) { return tokenAt(content, start) })
	for i := range found {
		if found[i].Kind == KindDeployToken {
			found[i].Secret, found[i].Attribution = deployUser(content)
		}
	}
	return found
}

func tokenAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	rest := content[start+len(stem):]
	for _, f := range families {
		if !bytes.HasPrefix(rest, []byte(f.prefix)) {
			continue
		}
		body := start + len(stem) + len(f.prefix)
		end, attribution, checksum, ok := shapeAt(content, start, body, f)
		if !ok {
			return detect.Token{}, false
		}
		return detect.Token{Kind: f.kind, Value: string(content[start:end]), Offset: start, Attribution: attribution, ChecksumVerified: checksum}, true
	}
	return detect.Token{}, false
}

// shapeAt matches the body of one family starting at body and returns
// where the token ends.
func shapeAt(content []byte, start, body int, f family) (end int, attribution string, checksum, ok bool) {
	switch f.kind {
	case KindPAT:
		if end, attribution, ok = routableAt(content, start, body); ok {
			return end, attribution, true, true
		}
	case KindRunnerToken:
		// A routable runner token carries its partition (`t1_`) before the payload.
		if body+3 < len(content) && content[body] == 't' && detect.IsDigit(content[body+1]) && content[body+2] == '_' {
			end, attribution, ok = routableAt(content, start, body+3)
			return end, attribution, ok, ok
		}
	case KindTriggerToken:
		end = body + triggerLen
		ok = end <= len(content) && detect.All(content[body:end], isLowerHex) && !isTokenByteAt(content, end)
		return end, "", false, ok
	case KindJobToken:
		n := detect.Span(content, body, jobPartitionMax+1, detect.IsAlnum)
		if n < jobPartitionMin || n > jobPartitionMax || body+n >= len(content) || content[body+n] != '_' {
			return 0, "", false, false
		}
		body += n + 1
		f.body = 20
	}
	end = body + f.body
	ok = end <= len(content) && detect.All(content[body:end], isTokenByte) && !isTokenByteAt(content, end)
	return end, "", false, ok
}

// deployUser finds the deploy token username written in the same object,
// `gitlab+deploy-token-<id>`, which a deploy token is useless without.
func deployUser(content []byte) (secret, attribution string) {
	i := bytes.Index(content, []byte(deployUserPrefix))
	if i < 0 {
		return "", "username not found nearby"
	}
	at := i + len(deployUserPrefix)
	n := detect.Span(content, at, 20, detect.IsDigit)
	if n == 0 || detect.AlnumAt(content, at+n) {
		return "", "username not found nearby"
	}
	user := string(content[i : at+n])
	return companion{Username: user}.encode(), "username " + user
}

// Instances implements detect.InstanceObserver: every host with a
// `gitlab` label in content, the way a self-managed GitLab is usually
// named (gitlab.example.com), as it was written, with its scheme and
// port. gitlab.com is tried anyway, and its subdomains and gitlab.io are
// the vendor's own sites, not an instance.
func (*Provider) Instances(content []byte) []string {
	return detect.ScanHosts(content, "gitlab.", func(host string) bool {
		return !vendorHost(host)
	})
}

func vendorHost(host string) bool {
	for _, suffix := range []string{"gitlab.com", "gitlab.io", "gitlab.net"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// Bind implements detect.InstanceObserver: the instances go into the
// token's companion material, next to the deploy username when there is
// one, for Verify to try.
func (*Provider) Bind(tok detect.Token, instances []string) detect.Token {
	c := decode(tok)
	c.Instances = instances
	tok.Secret = c.encode()
	return tok
}

func isTokenByte(c byte) bool { return detect.IsAlnum(c) || c == '_' || c == '-' }
func isLowerHex(c byte) bool  { return detect.IsDigit(c) || (c >= 'a' && c <= 'f') }

// isTokenByteAt reports whether content continues with a token byte at i,
// which would make the candidate part of a longer word.
func isTokenByteAt(content []byte, i int) bool {
	return i < len(content) && isTokenByte(content[i])
}
