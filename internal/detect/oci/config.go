package oci

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

// maxLayers is how many base64 layers the decoder peels: the
// .dockerconfigjson of a Kubernetes Secret and the auth field inside it.
const maxLayers = 2

// entry is one registry of a Docker config's auths map. credsStore and
// credHelpers are siblings of the map and never reach it; an entry that
// only names a helper is empty and yields nothing.
type entry struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// decode finds every registry login embedded in content, however it is
// wrapped, and the byte ranges of the encoded blobs it decoded.
func decode(content []byte) ([]Login, []span) {
	d := &decoder{}
	d.scan(content, 0, 0, false)
	return d.logins, d.consumed
}

type decoder struct {
	logins   []Login
	consumed []span
}

// scan looks through one layer of text: content sits at base in the
// scanned object and is layers deep in base64. Three shapes are looked
// for: the auths map of a Docker config, in the clear or escaped inside a
// JSON string; the dockerconfigjson field of a pull secret or Helm value,
// whose value is base64; and a Basic Authorization header aimed at a
// registry.
func (d *decoder) scan(content []byte, base, layers int, encoded bool) {
	for idx := 0; ; {
		i := bytes.Index(content[idx:], []byte("auths"))
		if i < 0 {
			break
		}
		at := idx + i
		idx = at + len("auths")
		switch {
		case at > 0 && content[at-1] == '"' && bytes.HasPrefix(content[idx:], []byte(`"`)):
			d.auths(content, idx+1, base, encoded)
		case at > 1 && content[at-1] == '"' && content[at-2] == '\\' && bytes.HasPrefix(content[idx:], []byte(`\"`)):
			d.escaped(content, at, base, layers, encoded)
		}
	}
	for idx := 0; ; {
		i := bytes.Index(content[idx:], []byte("dockerconfigjson"))
		if i < 0 {
			break
		}
		at := idx + i
		idx = at + len("dockerconfigjson")
		d.blob(content, idx, base, layers)
	}
	for idx := 0; ; {
		i := bytes.Index(content[idx:], []byte("Basic "))
		if i < 0 {
			break
		}
		at := idx + i
		idx = at + len("Basic ")
		d.basic(content, at, idx, base)
	}
}

// auths decodes the map that follows an "auths" key at position i (just
// past the closing quote) and emits one login per registry that has a
// secret. Positions inside an encoded layer mean nothing in the scanned
// object, so everything found there is placed at the blob's start.
func (d *decoder) auths(content []byte, i, base int, encoded bool) {
	i = skipSpace(content, i)
	if i >= len(content) || content[i] != ':' {
		return
	}
	i = skipSpace(content, i+1)
	if i >= len(content) || content[i] != '{' {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(content[i:]))
	var auths map[string]entry
	if dec.Decode(&auths) != nil {
		return
	}
	region := content[i : i+int(dec.InputOffset())]
	at := func(needle string) int {
		if j := bytes.Index(region, []byte(needle)); j >= 0 && !encoded {
			return base + i + j
		}
		return base
	}
	for _, host := range slices.Sorted(maps.Keys(auths)) {
		e := auths[host]
		user, pass := e.Username, e.Password
		fromAuth := false
		if e.Auth != "" {
			raw, ok := unbase64(e.Auth)
			if !ok {
				continue
			}
			if u, p, found := strings.Cut(string(raw), ":"); found {
				user, pass, fromAuth = u, p, true
			}
			if !encoded {
				d.consume(at(e.Auth), len(e.Auth))
			}
		}
		if pass == "" {
			continue
		}
		d.logins = append(d.logins, Login{Host: cleanHost(host), Username: user, Password: pass, Offset: at(strconv.Quote(host)), Encoded: encoded || fromAuth})
	}
}

// escaped handles a Docker config that sits as an escaped string inside
// JSON or a double-quoted YAML scalar: the enclosing string literal is
// unquoted and scanned as a layer of its own.
func (d *decoder) escaped(content []byte, at, base, layers int, encoded bool) {
	start := at - 2
	for start > 0 && (content[start] != '"' || content[start-1] == '\\') {
		start--
	}
	if start == 0 && content[0] != '"' {
		return
	}
	end := at
	for end < len(content) && (content[end] != '"' || content[end-1] == '\\') {
		end++
	}
	if end >= len(content) {
		return
	}
	var inner string
	if json.Unmarshal(content[start:end+1], &inner) != nil {
		return
	}
	d.scan([]byte(inner), base+start, layers, encoded)
}

// blob decodes the base64 value after a dockerconfigjson key at position i
// and scans the config inside it. A value that is not base64 (a JSON
// config in the clear under stringData) is left to the auths pass.
func (d *decoder) blob(content []byte, i, base, layers int) {
	if layers >= maxLayers {
		return
	}
	i = skipSpace(content, i)
	for i < len(content) && strings.IndexByte(`"':|>`, content[i]) >= 0 {
		i = skipSpace(content, i+1)
	}
	n := detect.Span(content, i, len(content)-i, isBase64)
	if n == 0 {
		return
	}
	raw, ok := unbase64(string(content[i : i+n]))
	if !ok || !bytes.Contains(raw, []byte("auths")) {
		return
	}
	d.consume(base+i, n)
	d.scan(raw, base+i, layers+1, true)
}

// basic decodes a `Basic <base64>` credential when it is an Authorization
// header and the text around it names a registry: a /v2/ URL or a known
// registry domain. Any other Basic header is left alone.
func (d *decoder) basic(content []byte, at, i, base int) {
	lineStart := bytes.LastIndexByte(content[:at], '\n') + 1
	if !bytes.Contains(bytes.ToLower(content[lineStart:at]), []byte("authorization")) {
		return
	}
	n := detect.Span(content, i, len(content)-i, isBase64)
	raw, ok := unbase64(string(content[i : i+n]))
	if !ok {
		return
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found || pass == "" || !printable(raw) {
		return
	}
	host := registryNear(content, at, i+n)
	if host == "" {
		return
	}
	d.consume(base+i, n)
	d.logins = append(d.logins, Login{Host: host, Username: user, Password: pass, Offset: base + at, Encoded: true})
}

func (d *decoder) consume(start, n int) {
	d.consumed = append(d.consumed, span{start, start + n})
}

// registryNear finds the registry host the text around a Basic header
// talks to: the host of a /v2/ URL first, else the full hostname around a
// known registry domain.
func registryNear(content []byte, start, end int) string {
	win, _ := around(content, start, end)
	for _, scheme := range []string{"https://", "http://"} {
		for i := 0; ; {
			j := bytes.Index(win[i:], []byte(scheme))
			if j < 0 {
				break
			}
			h := i + j + len(scheme)
			i = h
			n := detect.Span(win, h, 253, isHostChar)
			if rest := win[h+n:]; bytes.HasPrefix(rest, []byte("/v2")) && !detect.AlnumAt(rest, len("/v2")) {
				return string(win[h : h+n])
			}
		}
	}
	lower := bytes.ToLower(win)
	for _, domain := range registryDomains {
		if j := bytes.Index(lower, []byte(domain)); j >= 0 {
			s, e := j, j+len(domain)
			for s > 0 && isHostChar(win[s-1]) {
				s--
			}
			for e < len(win) && isHostChar(win[e]) {
				e++
			}
			return string(win[s:e])
		}
	}
	return ""
}

// cleanHost reduces the key of an auths entry to a host: Docker Hub's
// legacy `https://index.docker.io/v1/` becomes `index.docker.io`.
func cleanHost(key string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(key, "https://"), "http://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return host
}

// unbase64 decodes standard or URL-safe base64, padded or not.
func unbase64(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, true
		}
	}
	return nil, false
}

func printable(b []byte) bool {
	return detect.All(b, func(c byte) bool { return c >= 0x20 && c < 0x7f || c == '\n' || c == '\t' })
}

func skipSpace(content []byte, i int) int {
	for i < len(content) && (content[i] == ' ' || content[i] == '\t' || content[i] == '\n' || content[i] == '\r') {
		i++
	}
	return i
}

func isBase64(c byte) bool   { return detect.IsBase64URL(c) || c == '+' || c == '/' || c == '=' }
func isHostChar(c byte) bool { return detect.IsAlnum(c) || c == '.' || c == '-' || c == ':' }
