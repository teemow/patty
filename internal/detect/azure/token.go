package azure

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindClientSecret is the client secret of an Entra ID application; its
	// name is the secret itself, the tenant and client id travel apart.
	KindClientSecret detect.Kind = "azure-client-secret"
	// KindStorageAccountKey is one of the two access keys of a storage
	// account, reported only next to the account's name.
	KindStorageAccountKey detect.Kind = "azure-storage-account-key"
	// KindSASToken is a shared access signature; its name is the `sig`
	// value, the URL or query it came in travels apart.
	KindSASToken detect.Kind = "azure-sas-token"
)

const (
	// secretAnchor is the `Q~` every client secret has at its fifth
	// character, after three characters and a digit.
	secretAnchor   = "Q~"
	secretHead     = 4
	secretBodyMin  = 31
	secretBodyMax  = 34
	storageKeyBody = 86 // base64 of 64 random bytes, then "=="
	// guidWindow is how far behind its keyword a tenant or client id may
	// stand; nameWindow the same for a storage account name.
	guidWindow = 120
	nameWindow = 80
	// stringWindow is how far along its line a connection string is
	// searched for the account name.
	stringWindow = 512
	// accountNameMin and accountNameMax bound a storage account name.
	accountNameMin, accountNameMax = 3, 24
)

// tenantKeywords and clientKeywords name, in lower case, the words a tenant
// or client id stands behind: environment variables, Terraform arguments,
// the JSON of `az ad sp create-for-rbac` (appId, tenant) and `--sdk-auth`
// (clientId, tenantId), and the authority URLs a tenant id is part of.
var (
	tenantKeywords = []string{"tenant", "microsoftonline.com/", "sts.windows.net/"}
	clientKeywords = []string{"client_id", "clientid", "client-id", "appid", "app_id", "app-id", "applicationid", "application_id", "application-id"}
	// accountKeywords name a storage account: the variables, connection
	// string field and Terraform arguments; the endpoint hosts are handled
	// apart.
	accountKeywords = []string{"accountname", "account_name", "account-name", "storage_account", "storageaccount", "storage-account"}
	// storageHosts are the service endpoints of a storage account, which
	// the account name is the first label of.
	storageHosts = []string{".blob.core.windows.net", ".dfs.core.windows.net", ".file.core.windows.net", ".queue.core.windows.net", ".table.core.windows.net", ".web.core.windows.net"}
)

// principal is what Token.Secret carries for a client secret: the tenant
// and application the secret authenticates, when they were found nearby.
type principal struct {
	Tenant string `json:"tenant,omitempty"`
	Client string `json:"client,omitempty"`
}

func (p principal) encode() string {
	if p == (principal{}) {
		return ""
	}
	raw, _ := json.Marshal(p)
	return string(raw)
}

func decodePrincipal(tok detect.Token) principal {
	var p principal
	_ = json.Unmarshal([]byte(tok.Secret), &p)
	return p
}

// attribution says what was found next to the secret.
func (p principal) attribution() string {
	switch {
	case p.Tenant != "" && p.Client != "":
		return "app " + p.Client + " in tenant " + p.Tenant
	case p.Client != "":
		return "app " + p.Client + ", tenant id not found nearby"
	case p.Tenant != "":
		return "tenant " + p.Tenant + ", client id not found nearby"
	}
	return "tenant and client id not found nearby"
}

// Find implements detect.Provider: client secrets by their anchor, storage
// keys by their padding, signatures by their `sig=` parameter, each paired
// with what it needs from the same object.
func (p *Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	// What a pairing needs from the whole object is built once, the first
	// time a candidate asks for it: a lockfile holds thousands of hashes
	// shaped exactly like a storage key, and scanning the object again for
	// every one of them made the scan quadratic.
	lower := sync.OnceValue(func() []byte { return bytes.ToLower(content) })
	tenants := sync.OnceValue(func() []int { return guidsAfter(content, lower(), tenantKeywords) })
	clients := sync.OnceValue(func() []int { return guidsAfter(content, lower(), clientKeywords) })
	named := sync.OnceValue(func() []accountAt { return accounts(content, lower()) })
	found = detect.ScanPrefix(found, content, secretAnchor, func(start int) (detect.Token, bool) {
		tok, ok := clientSecretAt(content, start)
		if ok {
			pr := principal{Tenant: guidNear(content, tenants(), tok.Offset), Client: guidNear(content, clients(), tok.Offset)}
			tok.Secret, tok.Attribution = pr.encode(), pr.attribution()
		}
		return tok, ok
	})
	found = detect.ScanPrefix(found, content, "==", func(start int) (detect.Token, bool) {
		tok, ok := storageKeyAt(content, start)
		if !ok {
			return tok, false
		}
		account := accountNear(content, lower(), named(), tok.Offset, tok.Offset+len(tok.Value))
		if account == "" {
			return detect.Token{}, false
		}
		tok.Secret, tok.Attribution = account, "storage account "+account
		return tok, true
	})
	return detect.ScanPrefix(found, content, "sig=", func(start int) (detect.Token, bool) { return p.sasAt(content, start) })
}

// clientSecretAt matches the shape around a `Q~` anchor: three characters
// and a digit before it, 31 to 34 characters after, not part of a longer
// word. A dot right after a secret is punctuation.
func clientSecretAt(content []byte, anchor int) (detect.Token, bool) {
	start := anchor - secretHead
	if start < 0 || detect.WordBefore(content, start) || !detect.All(content[start:anchor-1], isSecretHead) || !detect.IsDigit(content[anchor-1]) {
		return detect.Token{}, false
	}
	body := anchor + len(secretAnchor)
	n := detect.Span(content, body, secretBodyMax+1, isSecretBody)
	if n > secretBodyMax && content[body+n-1] == '.' {
		n--
	}
	if n < secretBodyMin || n > secretBodyMax {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindClientSecret, Value: string(content[start : body+n]), Offset: start}, true
}

func isSecretHead(c byte) bool { return detect.IsAlnum(c) || c == '_' || c == '~' || c == '.' }
func isSecretBody(c byte) bool { return isSecretHead(c) || c == '-' }
func isBase64(c byte) bool     { return detect.IsAlnum(c) || c == '+' || c == '/' }

// storageKeyAt matches the 86 base64 characters before a `==`, bounded on
// both sides: a longer run is something else, and so is one without a
// storage account name nearby, which the caller checks.
func storageKeyAt(content []byte, padding int) (detect.Token, bool) {
	start := padding - storageKeyBody
	end := padding + 2
	if start < 0 || !detect.All(content[start:padding], isBase64) {
		return detect.Token{}, false
	}
	if start > 0 && isBase64(content[start-1]) {
		return detect.Token{}, false
	}
	if end < len(content) && (isBase64(content[end]) || content[end] == '=') {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindStorageAccountKey, Value: string(content[start:end]), Offset: start}, true
}

// guidNear picks, among the GUIDs that stand behind a keyword, the one
// closest to the credential at from; "" when there is none.
func guidNear(content []byte, guids []int, from int) string {
	best, bestDist := "", -1
	for _, guid := range guids {
		if dist := distance(guid, guid+guidLen, from, from); bestDist < 0 || dist < bestDist {
			best, bestDist = string(content[guid:guid+guidLen]), dist
		}
	}
	return best
}

// guidsAfter finds every GUID that stands within guidWindow bytes after an
// occurrence of one of the keywords. Keywords are matched in lower case.
func guidsAfter(content, lower []byte, keywords []string) []int {
	var out []int
	for _, kw := range keywords {
		for at := range occurrences(lower, kw) {
			if guid, ok := guidAfter(content, at+len(kw), guidWindow); ok {
				out = append(out, guid)
			}
		}
	}
	return out
}

// occurrences yields the offset of every occurrence of needle in content.
func occurrences(content []byte, needle string) func(func(int) bool) {
	return func(yield func(int) bool) {
		for idx := 0; ; {
			i := bytes.Index(content[idx:], []byte(needle))
			if i < 0 || !yield(idx+i) {
				return
			}
			idx += i + len(needle)
		}
	}
}

// distance ranks a companion in [cStart, cEnd) against the credential in
// [start, end): the gap between the two, with what follows the credential
// counting double, since the ids and names a credential belongs to are
// usually written before it, the way the AWS provider ranks a secret
// against its key id.
func distance(cStart, cEnd, start, end int) int {
	if cStart >= end {
		return 2 * (cStart - end)
	}
	return abs(start - cEnd)
}

// guidAfter finds where the first GUID within window bytes of pos starts.
func guidAfter(content []byte, pos, window int) (int, bool) {
	for i := pos; i < len(content) && i < pos+window; i++ {
		if guidAt(content, i) {
			return i, true
		}
	}
	return 0, false
}

const guidLen = 36

// guidAt reports whether a GUID (8-4-4-4-12 hexadecimal characters, not
// part of a longer word) starts at i.
func guidAt(content []byte, i int) bool {
	if i+guidLen > len(content) || detect.WordBefore(content, i) || detect.AlnumAt(content, i+guidLen) {
		return false
	}
	for j, c := range content[i : i+guidLen] {
		switch j {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !detect.IsHex(c) {
				return false
			}
		}
	}
	return true
}

// accountAt is a storage account name written in the scanned content, and
// where it starts.
type accountAt struct {
	name string
	at   int
}

// accounts lists every storage account name the content writes down: the
// first label of a storage endpoint host, and the name written after one
// of the account keywords.
func accounts(content, lower []byte) []accountAt {
	var out []accountAt
	for _, host := range storageHosts {
		for at := range occurrences(lower, host) {
			if name := labelBefore(content, at); name != "" {
				out = append(out, accountAt{name, at - len(name)})
			}
		}
	}
	for _, kw := range accountKeywords {
		for at := range occurrences(lower, kw) {
			if name, at := accountNameAfter(content, at+len(kw)); name != "" {
				out = append(out, accountAt{name, at})
			}
		}
	}
	return out
}

// accountNear finds the storage account a key belongs to: the AccountName
// of the connection string the key stands in, or the one of the accounts
// named anywhere in the content that is closest to the key. "" when there
// is none.
func accountNear(content, lower []byte, named []accountAt, start, end int) string {
	best, bestDist := "", -1
	consider := func(name string, at int) {
		if dist := distance(at, at+len(name), start, end); name != "" && (bestDist < 0 || dist < bestDist) {
			best, bestDist = name, dist
		}
	}
	// A connection string names the account on the same line, before or
	// after the key.
	if bytes.HasSuffix(lower[:start], []byte("accountkey=")) {
		lineStart := max(bytes.LastIndexByte(lower[:start], '\n')+1, start-stringWindow)
		lineEnd := min(len(lower), end+stringWindow)
		if nl := bytes.IndexByte(lower[end:lineEnd], '\n'); nl >= 0 {
			lineEnd = end + nl
		}
		if i := bytes.Index(lower[lineStart:lineEnd], []byte("accountname=")); i >= 0 {
			at := lineStart + i + len("accountname=")
			consider(accountNameAt(content, at), at)
		}
	}
	for _, a := range named {
		consider(a.name, a.at)
	}
	return best
}

// accountNameAt reads a storage account name, 3 to 24 lower-case letters
// and digits as Azure requires them, standing exactly at i and not
// continuing into a longer word.
func accountNameAt(content []byte, i int) string {
	n := detect.Span(content, i, accountNameMax+1, isNameChar)
	if n < accountNameMin || n > accountNameMax || detect.AlnumAt(content, i+n) {
		return ""
	}
	return string(content[i : i+n])
}

// accountNameAfter reads the name written after a keyword ending at i, and
// where it starts: the rest of the keyword's identifier (`_NAME`) is
// skipped, then the separators, then the name has to stand there.
func accountNameAfter(content []byte, i int) (string, int) {
	i += detect.Span(content, i, nameWindow, func(c byte) bool { return detect.IsAlnum(c) || c == '_' || c == '-' })
	i += detect.Span(content, i, nameWindow, func(c byte) bool { return strings.IndexByte(" \t=:\"'>", c) >= 0 })
	return accountNameAt(content, i), i
}

// labelBefore reads the host label that ends at i, which is where a
// storage endpoint suffix starts.
func labelBefore(content []byte, i int) string {
	start := i
	for start > 0 && isNameChar(content[start-1]) && i-start <= accountNameMax {
		start--
	}
	if start > 0 && (detect.IsAlnum(content[start-1]) || content[start-1] == '-' || content[start-1] == '_') {
		return ""
	}
	if n := i - start; n < accountNameMin || n > accountNameMax {
		return ""
	}
	return string(content[start:i])
}

func isNameChar(c byte) bool { return detect.IsDigit(c) || (c >= 'a' && c <= 'z') }

// signature is a shared access signature as found: the URL or bare query
// it came in, and the parameters that matter.
type signature struct {
	// Raw is the whole span, a URL with its query or a bare query string.
	Raw string
	// Resource is the URL without the query, "" for a bare token.
	Resource string
	Sig      string
	Expires  time.Time
	// Permissions and Scope are the sp and sr/ss parameters, for the report.
	Permissions, Scope string
}

// sasAt reads the query string around a `sig=` parameter, and the URL in
// front of it when there is one. A signature needs sv, se and sig; other
// signed URLs are left alone.
func (p *Provider) sasAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	from := start
	for from > 0 && isQueryChar(content[from-1]) {
		from--
	}
	to := start
	for to < len(content) && isQueryChar(content[to]) {
		to++
	}
	for to > from && strings.IndexByte(".,;:", content[to-1]) >= 0 {
		to--
	}
	span := string(content[from:to])
	sig, ok := parseSignature(span)
	if !ok {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindSASToken, Value: sig.Sig, Offset: from + len(span) - len(sig.Raw), Attribution: p.describe(sig), Secret: sig.Raw}, true
}

func isQueryChar(c byte) bool {
	return detect.IsAlnum(c) || strings.IndexByte("%&=._~:/+-?@!$*", c) >= 0
}

// sasParameters are the query parameters a shared access signature is made
// of; a bare token starts with one of them.
var sasParameters = []string{"sv", "ss", "srt", "sp", "se", "st", "spr", "sig", "sr", "si", "sip", "sdd", "skoid", "sktid", "skt", "ske", "sks", "skv"}

// parseSignature splits a span into resource and query and reads the SAS
// parameters; false when the query is not a shared access signature. A
// span without a URL is a bare token, and what stands in front of its
// first parameter (a variable name, a question mark) is not part of it.
func parseSignature(raw string) (signature, bool) {
	resource, query, hasURL := strings.Cut(raw, "?")
	if !hasURL || !strings.Contains(resource, "://") {
		resource, raw = "", raw[queryStart(raw):]
		query = raw
	}
	q, err := url.ParseQuery(query)
	if err != nil || q.Get("sv") == "" || q.Get("sig") == "" || q.Get("se") == "" {
		return signature{}, false
	}
	s := signature{Raw: raw, Resource: resource, Sig: q.Get("sig"), Permissions: q.Get("sp"), Scope: q.Get("sr")}
	if s.Scope == "" {
		s.Scope = q.Get("ss")
	}
	s.Expires, _ = parseTime(q.Get("se"))
	return s, true
}

// queryStart finds where the SAS parameters begin in a bare token: the
// first parameter name that stands at the start or right behind a
// separator. A name without a separator in front of it, a property such
// as `e.sig=` in a script, is passed over.
func queryStart(raw string) int {
	best := len(raw)
	for _, name := range sasParameters {
		needle := name + "="
		for at := strings.Index(raw, needle); at >= 0 && at < best; {
			if at == 0 || strings.IndexByte("&?=", raw[at-1]) >= 0 {
				best = at
				break
			}
			next := strings.Index(raw[at+1:], needle)
			if next < 0 {
				break
			}
			at += 1 + next
		}
	}
	if best == len(raw) {
		return 0
	}
	return best
}

// parseTime reads the ISO 8601 forms a SAS accepts: a full timestamp, one
// without seconds, or a date.
func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// describe is the attribution of a signature: what it is for, and until
// when.
func (p *Provider) describe(s signature) string {
	var parts []string
	if s.Resource != "" {
		if u, err := url.Parse(s.Resource); err == nil && u.Host != "" {
			parts = append(parts, "resource "+u.Host+u.Path)
		}
	} else {
		parts = append(parts, "bare token, resource unknown")
	}
	if s.Permissions != "" {
		parts = append(parts, "permissions "+s.Permissions)
	}
	switch {
	case s.Expires.IsZero():
		parts = append(parts, "expiry unreadable")
	case s.Expires.Before(p.now()):
		parts = append(parts, "expired "+s.Expires.UTC().Format("2006-01-02"))
	default:
		parts = append(parts, "expires "+s.Expires.UTC().Format("2006-01-02"))
	}
	return strings.Join(parts, ", ")
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
