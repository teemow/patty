package registry

import (
	"bytes"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

const (
	// KindHubLogin is a Docker Hub username with a password that is not a
	// Docker Hub token.
	KindHubLogin detect.Kind = "docker-hub-login"
	// KindQuayLogin is a quay.io username with a password that is not a
	// robot token.
	KindQuayLogin detect.Kind = "quay-login"
	// KindACRLogin is an Azure Container Registry login: an admin user, a
	// repository-scoped token or a service principal.
	KindACRLogin detect.Kind = "acr-login"
	// KindGHCRLogin is a ghcr.io login; its password is a GitHub token.
	KindGHCRLogin detect.Kind = "ghcr-login"
	// KindGCRLogin is a Google Container or Artifact Registry login.
	KindGCRLogin detect.Kind = "gcr-login"
	// KindECRLogin is an Amazon ECR login; its password is a 12-hour token.
	KindECRLogin detect.Kind = "ecr-login"
	// KindHarborLogin is a login to a Harbor registry.
	KindHarborLogin detect.Kind = "harbor-login"
	// KindRegistryLogin is a login to any other registry.
	KindRegistryLogin detect.Kind = "registry-login"
	// KindHubPAT is a Docker Hub personal access token (dckr_pat_).
	KindHubPAT detect.Kind = "docker-hub-pat"
	// KindHubOAT is a Docker Hub organization access token (dckr_oat_).
	KindHubOAT detect.Kind = "docker-hub-oat"
	// KindQuayRobot is the token of a Quay robot account, 64 upper-case
	// alphanumerics that are only a credential together with the robot's
	// `org+name` username.
	KindQuayRobot detect.Kind = "quay-robot-token"
	// KindQuayOAuth is a Quay OAuth access token, 40 alphanumerics.
	KindQuayOAuth detect.Kind = "quay-oauth-token"
)

const (
	hubPrefixLen = len("dckr_pat_")
	// Docker does not document the length of its tokens; the ones in the
	// wild have 27 characters after the prefix. The range leaves room.
	hubBodyMin  = 24
	hubBodyMax  = 40
	robotLen    = 64
	oauthLen    = 40
	quayAPIUser = "/api/v1/user/"
	// window is how far around a bare token its username or registry is
	// looked for.
	window = 512
)

// Login is the credential of one registry entry: what the decoder hands
// the provider.
type Login struct {
	Host, Username, Password string
	// Offset is where the entry, or the encoded blob holding it, starts.
	Offset int
	// Encoded reports whether the password came out of a base64 layer, so
	// no other provider has seen it in the clear.
	Encoded bool
}

// span is a byte range of content whose text was decoded into logins; a
// bare token candidate inside it is base64, not a token.
type span struct{ start, end int }

// Find implements detect.Provider. The config decoder runs first and
// consumes the encoded blobs it understands; the bare token shapes are
// then searched outside those blobs, and a token that is already the
// password of a decoded login is not reported twice.
func (p *Provider) Find(content []byte) []detect.Token {
	logins, consumed := decode(content)
	var found []detect.Token
	seen := map[string]bool{}
	for _, l := range logins {
		for _, tok := range p.tokens(l) {
			if !seen[string(tok.Kind)+":"+tok.Value] {
				seen[string(tok.Kind)+":"+tok.Value] = true
				found = append(found, tok)
			}
		}
	}
	for _, tok := range bare(content) {
		if !inside(consumed, tok.Offset) && !seen[string(tok.Kind)+":"+tok.Value] {
			found = append(found, tok)
		}
	}
	return found
}

// tokens turns one login into its findings: the login itself, or the
// Docker Hub or Quay token that is its password, plus the credential of
// another provider hidden in an encoded password.
func (p *Provider) tokens(l Login) []detect.Token {
	kind := kindFor(l.Host)
	user := l.Username
	if user == "" {
		user = "<anonymous>"
	}
	where := l.Host + ", user " + user
	switch {
	case kind == KindHubLogin && isHubToken(l.Password):
		return []detect.Token{{Kind: hubKind(l.Password), Value: l.Password, Offset: l.Offset, Secret: l.Username, Attribution: where}}
	case kind == KindQuayLogin && isRobotToken(l.Password) && strings.Contains(l.Username, "+"):
		return []detect.Token{{Kind: KindQuayRobot, Value: l.Password, Offset: l.Offset, Secret: l.Username, Attribution: where}}
	}
	if kind == KindECRLogin {
		where += ", temporary: expires within 12 hours of being minted"
	}
	login := detect.Token{Kind: kind, Value: l.Host + "/" + l.Username, Offset: l.Offset, Secret: l.Password, Attribution: where}
	peer, ok := p.peer(l.Password)
	if !ok {
		return []detect.Token{login}
	}
	login.Attribution += ", password is a " + p.kinds[peer.Kind] + ", reported separately"
	if !l.Encoded {
		return []detect.Token{login}
	}
	peer.Offset = l.Offset
	return []detect.Token{login, peer}
}

// peer reports whether the whole password is a credential of another
// provider, and which.
func (p *Provider) peer(password string) (detect.Token, bool) {
	if password == "" {
		return detect.Token{}, false
	}
	for _, provider := range p.peers {
		for _, tok := range provider.Find([]byte(password)) {
			if tok.Value == password {
				return tok, true
			}
		}
	}
	return detect.Token{}, false
}

// bare finds the token shapes that stand on their own: Docker Hub tokens
// by prefix, Quay robot tokens next to their robot's name, Quay OAuth
// tokens next to a quay.io mention.
func bare(content []byte) []detect.Token {
	var found []detect.Token
	for _, prefix := range []string{"dckr_pat_", "dckr_oat_"} {
		found = detect.ScanPrefix(found, content, prefix, func(start int) (detect.Token, bool) { return hubTokenAt(content, start) })
	}
	return quayTokens(found, content)
}

func hubTokenAt(content []byte, start int) (detect.Token, bool) {
	if detect.WordBefore(content, start) {
		return detect.Token{}, false
	}
	body := detect.Span(content, start+hubPrefixLen, hubBodyMax+1, detect.IsBase64URL)
	if body < hubBodyMin || body > hubBodyMax {
		return detect.Token{}, false
	}
	end := start + hubPrefixLen + body
	value := string(content[start:end])
	tok := detect.Token{Kind: hubKind(value), Value: value, Offset: start}
	if user := usernameNear(content, start, end); user != "" {
		tok.Secret = user
		tok.Attribution = "user " + user
	} else {
		tok.Attribution = "username not found nearby"
	}
	return tok, true
}

// isHubToken reports whether the whole string is a Docker Hub token.
func isHubToken(s string) bool {
	tok, ok := hubTokenAt([]byte(s), 0)
	return ok && len(tok.Value) == len(s)
}

func hubKind(value string) detect.Kind {
	if strings.HasPrefix(value, "dckr_oat_") {
		return KindHubOAT
	}
	return KindHubPAT
}

// quayTokens appends the Quay robot and OAuth tokens in content: maximal
// alphanumeric runs of the right length and case, word-bounded, that are
// not hexadecimal (a hash is not a token), and have their robot name or a
// quay.io mention within the window.
func quayTokens(found []detect.Token, content []byte) []detect.Token {
	for i := 0; i < len(content); {
		if !detect.IsAlnum(content[i]) {
			i++
			continue
		}
		start := i
		for i < len(content) && detect.IsAlnum(content[i]) {
			i++
		}
		run := content[start:i]
		if detect.WordBefore(content, start) || (i < len(content) && content[i] == '_') {
			continue
		}
		switch {
		case len(run) == robotLen && isRobotToken(string(run)):
			if robot := robotNear(content, start, i); robot != "" {
				found = append(found, detect.Token{Kind: KindQuayRobot, Value: string(run), Offset: start, Secret: robot, Attribution: "robot " + robot})
			}
		case len(run) == oauthLen && isOAuthToken(run) && mentions(content, start, i, "quay.io"):
			found = append(found, detect.Token{Kind: KindQuayOAuth, Value: string(run), Offset: start})
		}
	}
	return found
}

// isRobotToken reports whether s has the shape of a Quay robot token.
func isRobotToken(s string) bool {
	b := []byte(s)
	return len(b) == robotLen && detect.All(b, isUpperAlnum) && !detect.All(b, detect.IsHex)
}

func isOAuthToken(run []byte) bool {
	return detect.All(run, detect.IsAlnum) && !detect.All(run, detect.IsHex) &&
		bytes.ContainsFunc(run, isUpper) && bytes.ContainsFunc(run, isLower)
}

// around returns the window of content around [start, end).
func around(content []byte, start, end int) ([]byte, int) {
	from := max(0, start-window)
	return content[from:min(len(content), end+window)], from
}

// mentions reports whether word appears, in any case, within the window
// around the candidate.
func mentions(content []byte, start, end int, word string) bool {
	win, _ := around(content, start, end)
	return bytes.Contains(bytes.ToLower(win), []byte(word))
}

// robotNear finds a Quay robot name, `org+robot` in lower-case letters,
// digits and underscores, within the window around the candidate.
func robotNear(content []byte, start, end int) string {
	win, _ := around(content, start, end)
	for i := 0; ; {
		j := bytes.IndexByte(win[i:], '+')
		if j < 0 {
			return ""
		}
		plus := i + j
		i = plus + 1
		orgStart, robotEnd := plus, plus+1
		for orgStart > 0 && isRobotChar(win[orgStart-1]) {
			orgStart--
		}
		for robotEnd < len(win) && isRobotChar(win[robotEnd]) {
			robotEnd++
		}
		if orgStart == plus || robotEnd == plus+1 || boundaryBreaks(win, orgStart-1) || boundaryBreaks(win, robotEnd) {
			continue
		}
		return string(win[orgStart:robotEnd])
	}
}

// boundaryBreaks reports whether the byte at i continues a base64 run or a
// word, which rules the candidate out as a robot name.
func boundaryBreaks(win []byte, i int) bool {
	return i >= 0 && i < len(win) && (detect.IsAlnum(win[i]) || strings.IndexByte("+/=-", win[i]) >= 0)
}

// usernameNear finds the username a bare Docker Hub token was written down
// with: the word after `username`, `user` or `-u` in the window around the
// token, in the forms config files, CI variables and docker login commands
// use. The closest one wins.
func usernameNear(content []byte, start, end int) string {
	win, from := around(content, start, end)
	lower := bytes.ToLower(win)
	best, bestDist := "", len(win)+1
	for _, key := range []string{"username", "user", "-u "} {
		for i := 0; ; {
			j := bytes.Index(lower[i:], []byte(key))
			if j < 0 {
				break
			}
			at := i + j
			i = at + len(key)
			if (at > 0 && detect.IsAlnum(win[at-1])) || (key[len(key)-1] != ' ' && detect.AlnumAt(win, at+len(key))) {
				continue // part of a longer word
			}
			word := wordAfter(win, at+len(key))
			if word == "" || strings.HasPrefix(word, "dckr_") {
				continue
			}
			if dist := distance(at, start-from, end-from); dist < bestDist {
				best, bestDist = word, dist
			}
		}
	}
	return best
}

// wordAfter skips the separators after a keyword (`: `, `=`, `": "`) and
// returns the following word in the alphabet of registry usernames.
func wordAfter(win []byte, i int) string {
	for i < len(win) && strings.IndexByte(" \t:=\"'", win[i]) >= 0 {
		i++
	}
	n := detect.Span(win, i, 128, isUserChar)
	return string(win[i : i+n])
}

// distance is how far a keyword at position at is from the token span
// [start, end) within the window.
func distance(at, start, end int) int {
	switch {
	case at < start:
		return start - at
	case at >= end:
		return at - end
	}
	return 0
}

func inside(spans []span, offset int) bool {
	for _, s := range spans {
		if offset >= s.start && offset < s.end {
			return true
		}
	}
	return false
}

func isUpper(r rune) bool      { return r >= 'A' && r <= 'Z' }
func isLower(r rune) bool      { return r >= 'a' && r <= 'z' }
func isUpperAlnum(c byte) bool { return (c >= 'A' && c <= 'Z') || detect.IsDigit(c) }
func isRobotChar(c byte) bool  { return (c >= 'a' && c <= 'z') || detect.IsDigit(c) || c == '_' }
func isUserChar(c byte) bool   { return detect.IsAlnum(c) || strings.IndexByte("._-+@", c) >= 0 }
