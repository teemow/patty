package grafana

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"strconv"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindServiceAccountToken is a service account token (glsa_).
	KindServiceAccountToken detect.Kind = "grafana-service-account-token"
	// KindCloudToken is a Grafana Cloud access policy token (glc_).
	KindCloudToken detect.Kind = "grafana-cloud-access-policy-token"
	// KindLegacyAPIKey is an API key from before service accounts, base64
	// JSON starting with eyJrIjoi.
	KindLegacyAPIKey detect.Kind = "grafana-legacy-api-key"
)

const (
	saPrefix    = "glsa_"
	saSecretLen = 32
	saSumLen    = 8
	saLen       = len(saPrefix) + saSecretLen + 1 + saSumLen

	cloudPrefix          = "glc_"
	cloudMin, cloudMax   = 32, 400
	legacyPrefix         = "eyJrIjoi" // {"k":" in base64
	legacyMin, legacyMax = 40, 400
)

// Find implements detect.Provider. Three substring passes cover the three
// families; each candidate is checked for its exact shape, the service
// account token for its checksum, the other two for the JSON they encode.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	found = detect.ScanPrefix(found, content, saPrefix, func(start int) (detect.Token, bool) { return serviceAccountAt(content, start) })
	found = detect.ScanPrefix(found, content, cloudPrefix, func(start int) (detect.Token, bool) { return cloudAt(content, start) })
	return detect.ScanPrefix(found, content, legacyPrefix, func(start int) (detect.Token, bool) { return legacyAt(content, start) })
}

func serviceAccountAt(content []byte, start int) (detect.Token, bool) {
	end := start + saLen
	sep := start + len(saPrefix) + saSecretLen
	if detect.WordBefore(content, start) || end > len(content) || content[sep] != '_' ||
		!detect.All(content[start+len(saPrefix):sep], detect.IsAlnum) || !detect.All(content[sep+1:end], isLowerHex) || detect.AlnumAt(content, end) {
		return detect.Token{}, false
	}
	secret := string(content[start+len(saPrefix) : sep])
	if string(content[sep+1:end]) != Checksum(secret) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindServiceAccountToken, Value: string(content[start:end]), Offset: start, ChecksumVerified: true}, true
}

// Checksum computes the eight hex characters Grafana appends to the 32
// random characters of a service account token: the CRC32 (IEEE) of
// `glsa_` followed by the secret, rendered byte by byte from the least
// significant one, as Grafana's satokengen does. Exported so callers and
// tests can construct well-formed tokens without hard-coding any.
func Checksum(secret string) string {
	sum := crc32.ChecksumIEEE([]byte(saPrefix + secret))
	return hex.EncodeToString([]byte{byte(sum), byte(sum >> 8), byte(sum >> 16), byte(sum >> 24)})
}

// cloudToken is the JSON a Grafana Cloud access policy token encodes.
type cloudToken struct {
	Org  string `json:"o"`
	Name string `json:"n"`
	Key  string `json:"k"`
	Meta struct {
		Region string `json:"r"`
	} `json:"m"`
}

func cloudAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	body := start + len(cloudPrefix)
	n := detect.Span(content, body, cloudMax+1, isBase64Any)
	n += detect.Span(content, body+n, 3, func(c byte) bool { return c == '=' })
	if n < cloudMin || n > cloudMax || detect.AlnumAt(content, body+n) {
		return detect.Token{}, false
	}
	ct, ok := DecodeCloud(string(content[body : body+n]))
	if !ok {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindCloudToken, Value: string(content[start : body+n]), Offset: start, Attribution: ct.attribution()}, true
}

// DecodeCloud reads the JSON body of a Cloud token, the part after `glc_`,
// in either base64 alphabet, with or without padding. A body that is not
// JSON with an org and a key is not a token.
func DecodeCloud(body string) (cloudToken, bool) {
	var ct cloudToken
	raw, ok := decodeBase64(body)
	if !ok || json.Unmarshal(raw, &ct) != nil || ct.Org == "" || ct.Key == "" {
		return cloudToken{}, false
	}
	return ct, true
}

func (ct cloudToken) attribution() string {
	parts := []string{"org " + ct.Org}
	if ct.Name != "" {
		parts = append(parts, "token "+ct.Name)
	}
	if ct.Meta.Region != "" {
		parts = append(parts, "region "+ct.Meta.Region)
	}
	return strings.Join(parts, ", ")
}

// legacyKey is the JSON a legacy API key encodes, as apikeygen wrote it.
type legacyKey struct {
	Key   string `json:"k"`
	Name  string `json:"n"`
	OrgID int64  `json:"id"`
}

func legacyAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	n := detect.Span(content, start, legacyMax+1, isBase64Std)
	n += detect.Span(content, start+n, 3, func(c byte) bool { return c == '=' })
	if n < legacyMin || n > legacyMax || detect.AlnumAt(content, start+n) {
		return detect.Token{}, false
	}
	var k legacyKey
	raw, ok := decodeBase64(string(content[start : start+n]))
	if !ok || json.Unmarshal(raw, &k) != nil || k.Key == "" || k.Name == "" {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindLegacyAPIKey, Value: string(content[start : start+n]), Offset: start, Attribution: "key " + k.Name + ", org id " + strconv.FormatInt(k.OrgID, 10)}, true
}

// decodeBase64 tries the standard and URL alphabets, padded and raw.
func decodeBase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, true
		}
	}
	return nil, false
}

// Instances implements detect.InstanceObserver: every host with a
// `grafana` label in content, the way a Grafana is usually named
// (grafana.example.com, example.grafana.net), as it was written, with its
// scheme and port. grafana.com and its subdomains are the vendor's own
// sites, grafana.github.io its GitHub Pages, not an instance.
func (*Provider) Instances(content []byte) []string {
	return detect.ScanHosts(content, "grafana.", func(host string) bool {
		return !vendorHost(host)
	})
}

func vendorHost(host string) bool {
	for _, suffix := range []string{"grafana.com", "grafana.org", "github.io"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return host == "grafana.net" || host == "www.grafana.net"
}

// Bind implements detect.InstanceObserver: the instances go into the
// token's companion material, one per line, for Verify to try.
func (*Provider) Bind(tok detect.Token, instances []string) detect.Token {
	if tok.Kind == KindCloudToken {
		return tok // bound to grafana.com by construction
	}
	tok.Secret = strings.Join(instances, "\n")
	return tok
}

// bound returns the instances Bind recorded on the token.
func bound(tok detect.Token) []string {
	if tok.Secret == "" {
		return nil
	}
	return strings.Split(tok.Secret, "\n")
}

func isLowerHex(c byte) bool  { return detect.IsDigit(c) || (c >= 'a' && c <= 'f') }
func isBase64Std(c byte) bool { return detect.IsAlnum(c) || c == '+' || c == '/' }
func isBase64Any(c byte) bool { return isBase64Std(c) || c == '-' || c == '_' }
