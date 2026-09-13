package openai

import "github.com/teemow/patty/internal/detect"

const (
	// KindProject is a project-scoped key (sk-proj-), the kind the platform issues by default.
	KindProject detect.Kind = "openai-project-key"
	// KindServiceAccount is the key of a project's service account (sk-svcacct-).
	KindServiceAccount detect.Kind = "openai-service-account-key"
	// KindAdmin is an organization admin key (sk-admin-), which manages the
	// organization rather than calling models.
	KindAdmin detect.Kind = "openai-admin-key"
	// KindLegacy is a user key from before projects (sk- and 20 characters
	// on either side of the marker).
	KindLegacy detect.Kind = "openai-legacy-key"
)

// Marker is what every OpenAI key contains at a fixed position: "OpenAI"
// in base64. The scan looks for it and checks the shape around it.
const Marker = "T3BlbkFJ"

const (
	legacyPrefix = "sk-"
	legacyHalf   = 20
)

// bodyLens are the documented lengths of the base64url runs on either side
// of the marker in a project, service account or admin key; each side has
// one of them. Anything else is not a key.
var bodyLens = []int{74, 58}

// prefixes start the keys with a fixed body length.
var prefixes = []struct {
	prefix string
	kind   detect.Kind
}{
	{"sk-proj-", KindProject},
	{"sk-svcacct-", KindServiceAccount},
	{"sk-admin-", KindAdmin},
}

// Find implements detect.Provider. One substring pass for the marker, then
// the exact shape around each occurrence: a run of one of the documented
// lengths on each side, the family prefix before the left run, and no
// continuation into a longer word on either end.
func (*Provider) Find(content []byte) []detect.Token {
	return detect.ScanPrefix(nil, content, Marker, func(at int) (detect.Token, bool) { return keyAround(content, at) })
}

func keyAround(content []byte, at int) (detect.Token, bool) {
	after := at + len(Marker)
	for _, right := range bodyLens {
		end := after + right
		if end > len(content) || !detect.All(content[after:end], detect.IsBase64URL) || detect.Base64URLAt(content, end) {
			continue
		}
		for _, left := range bodyLens {
			bodyStart := at - left
			if bodyStart < 0 || !detect.All(content[bodyStart:at], detect.IsBase64URL) {
				continue
			}
			for _, f := range prefixes {
				start := bodyStart - len(f.prefix)
				if start < 0 || string(content[start:bodyStart]) != f.prefix || detect.WordBefore(content, start) {
					continue
				}
				return detect.Token{Kind: f.kind, Value: string(content[start:end]), Offset: start}, true
			}
		}
	}
	return legacyAround(content, at)
}

func legacyAround(content []byte, at int) (detect.Token, bool) {
	bodyStart := at - legacyHalf
	start := bodyStart - len(legacyPrefix)
	end := at + len(Marker) + legacyHalf
	if start < 0 || end > len(content) || string(content[start:bodyStart]) != legacyPrefix ||
		!detect.All(content[bodyStart:at], detect.IsAlnum) || !detect.All(content[at+len(Marker):end], detect.IsAlnum) ||
		detect.WordBefore(content, start) || detect.Base64URLAt(content, end) {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindLegacy, Value: string(content[start:end]), Offset: start}, true
}
