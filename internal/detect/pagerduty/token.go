package pagerduty

import (
	"bytes"

	"go.yaml.in/yaml/v3"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindAPIKey is a REST API key: a general access key (y_) or a user
	// key (u+).
	KindAPIKey detect.Kind = "pagerduty-api-key"
	// KindRoutingKey is the integration key an Events API v2 (or v1
	// service_key) integration is addressed by.
	KindRoutingKey detect.Kind = "pagerduty-routing-key"
)

const (
	keyBodyLen    = 18
	routingKeyLen = 32
	// generalPrefix starts a general access key, userPrefix a user key.
	generalPrefix, userPrefix = "y_", "u+"
)

// markers are the words that, somewhere in the same object, make a `y_`
// candidate a PagerDuty key rather than the tail of some identifier; a
// `u+` key is distinctive enough on its own. Matched case-insensitively.
var markers = [][]byte{[]byte("pagerduty"), []byte("pd_"), []byte("api.pagerduty.com"), []byte("token token=")}

// routingKeyNames are the configuration keys whose value is a routing key,
// as Alertmanager (`routing_key`, `service_key`), Terraform's
// pagerduty_service_integration (`integration_key`), environment files
// (`PAGERDUTY_ROUTING_KEY`, `PD_ROUTING_KEY`) and plain YAML or JSON
// spell them. A name found as the tail of a longer word
// (`pagerduty_routing_key`) counts, with the whole word as the
// attribution; one followed by more word characters (`routing_key_file`)
// does not.
var routingKeyNames = []string{"routing_key", "ROUTING_KEY", "service_key", "SERVICE_KEY", "integration_key", "INTEGRATION_KEY"}

// alertmanagerMarker is what an Alertmanager configuration with a
// PagerDuty receiver spells; only such content is parsed as YAML.
const alertmanagerMarker = "pagerduty_configs"

// Find implements detect.Provider. Two substring passes find the API key
// prefixes; each candidate is checked for its exact shape and, for the
// less distinctive `y_` prefix, for a PagerDuty marker in the same object.
// Routing keys have no shape of their own and are found by position only:
// as the value of a configuration key that names one, and inside the
// pagerduty_configs of an Alertmanager receiver, which the receiver's name
// is read from.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	marked, checked := false, false
	hasMarker := func() bool {
		if !checked {
			checked = true
			lower := bytes.ToLower(content)
			for _, m := range markers {
				if bytes.Contains(lower, m) {
					marked = true
					break
				}
			}
		}
		return marked
	}
	found = detect.ScanPrefix(found, content, generalPrefix, func(start int) (detect.Token, bool) {
		tok, ok := apiKeyAt(content, start, isGeneralByte)
		return tok, ok && hasMarker()
	})
	found = detect.ScanPrefix(found, content, userPrefix, func(start int) (detect.Token, bool) {
		return apiKeyAt(content, start, isUserByte)
	})
	return routingKeys(found, content)
}

// apiKeyAt matches a two-character prefix followed by eighteen bytes of
// the family's alphabet, standing on its own: nothing of either alphabet
// right before or after it, so a key is never cut out of a longer run.
func apiKeyAt(content []byte, start int, ok func(byte) bool) (detect.Token, bool) {
	end := start + len(generalPrefix) + keyBodyLen
	if end > len(content) || (start > 0 && isUserByte(content[start-1])) || !detect.All(content[start+2:end], ok) || (end < len(content) && (isUserByte(content[end]) || content[end] == '=')) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindAPIKey, Value: string(content[start:end]), Offset: start}, true
}

// routingKeys appends every routing key found by position: first the ones
// an Alertmanager configuration places under a receiver, then the values
// of the configuration keys that name one. A key the receiver already
// accounts for is not reported a second time under its bare name.
func routingKeys(found []detect.Token, content []byte) []detect.Token {
	seen := map[string]bool{}
	if bytes.Contains(content, []byte(alertmanagerMarker)) {
		for _, tok := range alertmanagerKeys(content) {
			seen[tok.Value] = true
			found = append(found, tok)
		}
	}
	for _, name := range routingKeyNames {
		found = detect.ScanPrefix(found, content, name, func(start int) (detect.Token, bool) {
			tok, ok := namedValueAt(content, start, len(name))
			if !ok || seen[tok.Value] {
				return detect.Token{}, false
			}
			seen[tok.Value] = true
			return tok, true
		})
	}
	return found
}

// namedValueAt reads the value written after the configuration key that
// ends at start+n: an optional closing quote, `:` or `=`, an optional
// opening quote, then exactly 32 lower-case hex characters standing on
// their own. The token's offset is the value's, its attribution the whole
// key word.
func namedValueAt(content []byte, start, n int) (detect.Token, bool) {
	keyStart := start
	for keyStart > 0 && isWordByte(content[keyStart-1]) {
		keyStart--
	}
	pos := start + n
	if pos < len(content) && isWordByte(content[pos]) {
		return detect.Token{}, false
	}
	pos = skip(content, pos, 1, isQuote)
	pos = skip(content, pos, 8, isSpace)
	if pos >= len(content) || (content[pos] != ':' && content[pos] != '=') {
		return detect.Token{}, false
	}
	pos = skip(content, pos+1, 8, isSpace)
	pos = skip(content, pos, 1, isQuote)
	end := pos + routingKeyLen
	if end > len(content) || !detect.All(content[pos:end], isLowerHex) || detect.AlnumAt(content, end) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindRoutingKey, Value: string(content[pos:end]), Offset: pos, Attribution: "under " + string(content[keyStart:start+n])}, true
}

// alertmanagerKeys reads the routing and service keys of every PagerDuty
// receiver in the Alertmanager configurations content holds, attributed
// to the receiver. A receiver is any mapping with a pagerduty_configs
// list, wherever it sits: at the top of alertmanager.yml, or under the
// values of a Helm chart that renders one.
func alertmanagerKeys(content []byte) []detect.Token {
	var out []detect.Token
	for _, doc := range detect.Documents(content) {
		root, ok := doc.Parse()
		if !ok {
			continue
		}
		walk(root, func(receiver *yaml.Node) {
			for _, c := range detect.Child(receiver, alertmanagerMarker).Content {
				for _, key := range []string{"routing_key", "service_key"} {
					v := detect.Child(c, key)
					if v == nil || v.Kind != yaml.ScalarNode || len(v.Value) != routingKeyLen || !detect.All([]byte(v.Value), isLowerHex) {
						continue
					}
					offset := doc.Offset(v)
					if offset < len(content) && isQuote(content[offset]) {
						offset++ // the node starts at its quote, the key after it
					}
					out = append(out, detect.Token{Kind: KindRoutingKey, Value: v.Value, Offset: offset, Attribution: key + " of receiver " + detect.Scalar(receiver, "name") + " in Alertmanager config"})
				}
			}
		})
	}
	return out
}

// walk calls fn on every mapping below n that holds a pagerduty_configs
// list.
func walk(n *yaml.Node, fn func(receiver *yaml.Node)) {
	switch n.Kind {
	case yaml.MappingNode:
		if configs := detect.Child(n, alertmanagerMarker); configs != nil && configs.Kind == yaml.SequenceNode {
			fn(n)
		}
		for i := 1; i < len(n.Content); i += 2 {
			walk(n.Content[i], fn)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			walk(c, fn)
		}
	}
}

// skip advances pos over at most limit bytes accepted by ok.
func skip(content []byte, pos, limit int, ok func(byte) bool) int {
	return pos + detect.Span(content, pos, limit, ok)
}

func isGeneralByte(c byte) bool { return detect.IsAlnum(c) || c == '_' || c == '-' }
func isUserByte(c byte) bool    { return isGeneralByte(c) || c == '+' || c == '/' }
func isWordByte(c byte) bool    { return detect.IsAlnum(c) || c == '_' }
func isLowerHex(c byte) bool    { return detect.IsDigit(c) || (c >= 'a' && c <= 'f') }
func isQuote(c byte) bool       { return c == '"' || c == '\'' }
func isSpace(c byte) bool       { return c == ' ' || c == '\t' }
