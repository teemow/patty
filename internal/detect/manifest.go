package detect

import (
	"bytes"
	"encoding/base64"
	"strings"

	"go.yaml.in/yaml/v3"
)

// maxSecretValue caps how much a single Secret value may decode to before
// it is scanned; a certificate bundle fits, a container image does not.
const maxSecretValue = 1 << 20

// Secret is one Kubernetes Secret manifest found in scanned content, with
// every value it carries decoded: the base64 under data and the clear text
// under stringData. A manifest is a leak whatever its values look like, so
// the parse keeps every key and says why a value was not decoded.
type Secret struct {
	Namespace string
	Name      string
	// Type is the Secret's type, "" for Opaque.
	Type string
	// Offset is where the manifest's kind is written in the content.
	Offset int
	// Sops reports that the manifest carries a sops metadata block: its
	// values are ciphertext and nothing about them is a finding.
	Sops   bool
	Values []SecretValue
}

// SecretValue is one entry of a Secret's data or stringData map.
type SecretValue struct {
	Key string
	// Offset is where the key is written in the content, which is where a
	// finding inside the value is placed; End is where the next key, or the
	// document, starts. A provider's own finding between the two sits in
	// this value.
	Offset, End int
	// Value is the decoded material, nil when Skipped says why not.
	Value []byte
	// Skipped names the reason a value was left alone: empty, templated,
	// encrypted (a sops ENC[…] value), not base64, or too large.
	Skipped string
}

// Ref names the manifest the way kubectl does: namespace/name, or the bare
// name when the manifest sets no namespace.
func (s Secret) Ref() string {
	if s.Namespace == "" {
		return s.Name
	}
	return s.Namespace + "/" + s.Name
}

// Plaintext returns the values that hold material in the clear: decoded and
// not skipped.
func (s Secret) Plaintext() []SecretValue {
	var out []SecretValue
	for _, v := range s.Values {
		if v.Skipped == "" {
			out = append(out, v)
		}
	}
	return out
}

// Secrets finds every Kubernetes Secret manifest in content: YAML or JSON,
// one document or several separated by `---`, on their own or as items of a
// List. Content that does not spell `kind: Secret` costs one substring
// search. A document that does not parse, a Helm template with bare `{{`
// blocks, is skipped rather than guessed at.
func Secrets(content []byte) []Secret {
	if !HasKind(content, "Secret") {
		return nil
	}
	var out []Secret
	for _, doc := range Documents(content) {
		root, ok := doc.Parse()
		if !ok {
			continue
		}
		for _, obj := range items(root) {
			if s, ok := secretOf(obj, doc); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// HasKind reports whether content spells `kind: <kind>` somewhere, in YAML
// or JSON, with or without quotes: the cheap test before parsing anything.
func HasKind(content []byte, kind string) bool {
	needle := []byte(kind)
	for idx := 0; ; {
		i := bytes.Index(content[idx:], needle)
		if i < 0 {
			return false
		}
		at := idx + i
		idx = at + len(needle)
		if AlnumAt(content, at+len(needle)) {
			continue
		}
		j := at
		for j > 0 && strings.IndexByte(` "':`, content[j-1]) >= 0 {
			j--
		}
		if j >= 4 && string(content[j-4:j]) == "kind" && !WordBefore(content, j-4) {
			return true
		}
	}
}

// Document is one YAML document of a stream, and where it starts in the
// scanned content. JSON is YAML, so a JSON object is one Document.
type Document struct {
	Body []byte
	// Start is the byte offset of Body in the content it was cut from.
	Start  int
	starts []int
}

// Documents splits a YAML stream at its `---` separators, so a document
// that does not parse costs only itself.
func Documents(content []byte) []*Document {
	var docs []*Document
	start := 0
	for i := 0; i <= len(content); {
		j := bytes.Index(content[i:], []byte("---"))
		if j < 0 {
			break
		}
		at := i + j
		atLineStart := at == 0 || content[at-1] == '\n'
		rest := content[at+3:]
		endsLine := len(rest) == 0 || rest[0] == '\n' || rest[0] == '\r' || rest[0] == ' '
		if atLineStart && endsLine {
			docs = append(docs, &Document{Body: content[start:at], Start: start})
			start = at + 3
		}
		i = at + 3
	}
	return append(docs, &Document{Body: content[start:], Start: start})
}

// Parse decodes the document into a node tree; false when it is not YAML,
// a Helm template with bare `{{ }}` blocks, or holds nothing.
func (d *Document) Parse() (*yaml.Node, bool) {
	var node yaml.Node
	if yaml.Unmarshal(d.Body, &node) != nil || node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		return nil, false
	}
	return node.Content[0], true
}

// Offset turns the line and column of a node into a byte offset in the
// scanned content.
func (d *Document) Offset(n *yaml.Node) int {
	if d.starts == nil {
		d.starts = []int{0}
		for i, c := range d.Body {
			if c == '\n' {
				d.starts = append(d.starts, i+1)
			}
		}
	}
	line := n.Line - 1
	if line < 0 || line >= len(d.starts) {
		return d.Start
	}
	return d.Start + min(d.starts[line]+n.Column-1, len(d.Body))
}

// Child returns the value node under key in a mapping, or nil.
func Child(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// Scalar returns the scalar value under key in a mapping, or "".
func Scalar(m *yaml.Node, key string) string {
	if v := Child(m, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

// items returns the objects a document holds: the object itself, or the
// items of a List.
func items(node *yaml.Node) []*yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	if kind := Scalar(node, "kind"); kind == "List" {
		if list := Child(node, "items"); list != nil && list.Kind == yaml.SequenceNode {
			return list.Content
		}
		return nil
	}
	return []*yaml.Node{node}
}

// secretOf reads one object as a Secret when its kind says so.
func secretOf(obj *yaml.Node, doc *Document) (Secret, bool) {
	kindNode := Child(obj, "kind")
	if kindNode == nil || kindNode.Value != "Secret" {
		return Secret{}, false
	}
	s := Secret{Type: Scalar(obj, "type"), Offset: doc.Offset(kindNode), Sops: Child(obj, "sops") != nil}
	if meta := Child(obj, "metadata"); meta != nil {
		s.Namespace = Scalar(meta, "namespace")
		s.Name = Scalar(meta, "name")
	}
	s.Values = append(s.Values, values(obj, "data", doc, true)...)
	s.Values = append(s.Values, values(obj, "stringData", doc, false)...)
	return s, true
}

// values decodes one of the two maps of a Secret; encoded says whether the
// values are base64. Each value's span ends where the next key starts,
// the next key of the object for the last one.
func values(obj *yaml.Node, key string, doc *Document, encoded bool) []SecretValue {
	m, end := Child(obj, key), doc.Start+len(doc.Body)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(obj.Content); i += 2 {
		if obj.Content[i].Value == key && i+2 < len(obj.Content) {
			end = doc.Offset(obj.Content[i+2])
		}
	}
	var out []SecretValue
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		sv := SecretValue{Key: k.Value, Offset: doc.Offset(k), End: end}
		if i+2 < len(m.Content) {
			sv.End = doc.Offset(m.Content[i+2])
		}
		sv.Value, sv.Skipped = decodeValue(v, encoded)
		out = append(out, sv)
	}
	return out
}

func decodeValue(v *yaml.Node, encoded bool) ([]byte, string) {
	if v.Kind != yaml.ScalarNode {
		return nil, "templated"
	}
	raw := strings.TrimSpace(v.Value)
	switch {
	case raw == "":
		return nil, "empty"
	case strings.HasPrefix(raw, "ENC["):
		return nil, "encrypted"
	case templated(raw):
		return nil, "templated"
	}
	if !encoded {
		return []byte(raw), ""
	}
	raw = strings.Join(strings.Fields(raw), "")
	dec, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		if dec, err = base64.RawStdEncoding.DecodeString(raw); err != nil {
			return nil, "not base64"
		}
	}
	if len(dec) > maxSecretValue {
		return nil, "too large"
	}
	return dec, ""
}

// templated reports whether a value is a placeholder for something filled
// in at deploy time: a Helm or Go template, a shell or kustomize variable,
// a Helm values reference.
func templated(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, "${") || strings.Contains(s, ".Values")
}
