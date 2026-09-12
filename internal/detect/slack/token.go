package slack

import "github.com/teemow/patty/internal/detect"

const (
	// KindBot is a bot token (xoxb-).
	KindBot detect.Kind = "slack-bot-token"
	// KindUser is a user token (xoxp-).
	KindUser detect.Kind = "slack-user-token"
	// KindApp is an app-level token for Socket Mode and events (xapp-).
	KindApp detect.Kind = "slack-app-token"
	// KindRefresh is a refresh token of a rotating or configuration token (xoxe-1-).
	KindRefresh detect.Kind = "slack-refresh-token"
	// KindConfig is an app configuration token, which shares its shape with
	// the short-lived access token of an app that rotates tokens (xoxe.xoxb-1-, xoxe.xoxp-1-).
	KindConfig detect.Kind = "slack-config-token"
	// KindWebhook is an incoming webhook URL (https://hooks.slack.com/...).
	KindWebhook detect.Kind = "slack-webhook"
)

const (
	idMin, idMax                 = 10, 13 // digits in the numeric team, user and bot ids
	botSecretLen                 = 24
	userSecretMin, userSecretMax = 28, 34
	appSecretLen                 = 64
	appIDMin, appIDMax           = 8, 12 // characters after the leading A of an app id
	slugMin, slugMax             = 8, 11 // characters after the leading letter of a T/B/A webhook id
	webhookSecretLen             = 24
	pathSecretMin, pathSecretMax = 20, 64   // last segment of a workflow or trigger webhook
	xoxeMin, xoxeMax             = 40, 1024 // opaque body of a refresh or configuration token
)

// Find implements detect.Provider. Five substring passes cover every family;
// the `xoxb-`, `xoxp-` and `xapp-` prefixes are followed by numeric ids
// whose lengths are checked exactly, so a `xoxb-` inside a `xoxe.xoxb-1-`
// token never matches on its own.
func (*Provider) Find(content []byte) []detect.Token {
	var found []detect.Token
	found = detect.ScanPrefix(found, content, "xoxb-", func(start int) (detect.Token, bool) { return botAt(content, start) })
	found = detect.ScanPrefix(found, content, "xoxp-", func(start int) (detect.Token, bool) { return userAt(content, start) })
	found = detect.ScanPrefix(found, content, "xapp-1-", func(start int) (detect.Token, bool) { return appAt(content, start) })
	found = detect.ScanPrefix(found, content, "xoxe", func(start int) (detect.Token, bool) { return xoxeAt(content, start) })
	return detect.ScanPrefix(found, content, hooksOrigin+"/", func(start int) (detect.Token, bool) { return webhookAt(content, start) })
}

// groups reads n dash-separated groups starting at pos, each a run of
// between lo and hi bytes accepted by ok and followed by '-'. It returns the
// groups and the position after the last dash.
func groups(content []byte, pos, n, lo, hi int, ok func(byte) bool) ([]string, int, bool) {
	out := make([]string, 0, n)
	for range n {
		l := detect.Span(content, pos, hi+1, ok)
		if l < lo || l > hi || pos+l >= len(content) || content[pos+l] != '-' {
			return nil, 0, false
		}
		out = append(out, string(content[pos:pos+l]))
		pos += l + 1
	}
	return out, pos, true
}

// secret checks that content[pos:] starts with a run of between lo and hi
// bytes accepted by ok that is not followed by another alphanumeric byte.
func secret(content []byte, pos, lo, hi int, ok func(byte) bool) (int, bool) {
	l := detect.Span(content, pos, hi+1, ok)
	if l < lo || l > hi || detect.AlnumAt(content, pos+l) {
		return 0, false
	}
	return pos + l, true
}

func botAt(content []byte, start int) (detect.Token, bool) {
	ids, pos, ok := groups(content, start+len("xoxb-"), 2, idMin, idMax, detect.IsDigit)
	if !ok {
		return detect.Token{}, false
	}
	end, ok := secret(content, pos, botSecretLen, botSecretLen, detect.IsAlnum)
	if !ok {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindBot, Value: string(content[start:end]), Offset: start, Attribution: "team " + ids[0] + ", bot " + ids[1]}, true
}

func userAt(content []byte, start int) (detect.Token, bool) {
	ids, pos, ok := groups(content, start+len("xoxp-"), 3, idMin, idMax, detect.IsDigit)
	if !ok {
		return detect.Token{}, false
	}
	end, ok := secret(content, pos, userSecretMin, userSecretMax, detect.IsAlnum)
	if !ok {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindUser, Value: string(content[start:end]), Offset: start, Attribution: "team " + ids[0] + ", user " + ids[1]}, true
}

func appAt(content []byte, start int) (detect.Token, bool) {
	pos := start + len("xapp-1-")
	if pos >= len(content) || content[pos] != 'A' {
		return detect.Token{}, false
	}
	ids, pos, ok := groups(content, pos+1, 1, appIDMin, appIDMax, isUpperAlnum)
	if !ok {
		return detect.Token{}, false
	}
	if _, pos, ok = groups(content, pos, 1, idMin, idMax, detect.IsDigit); !ok {
		return detect.Token{}, false
	}
	end, ok := secret(content, pos, appSecretLen, appSecretLen, detect.IsHex)
	if !ok {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindApp, Value: string(content[start:end]), Offset: start, Attribution: "app A" + ids[0]}, true
}

// xoxeAt matches the refresh token `xoxe-1-…` and the configuration or
// rotating access tokens `xoxe.xoxb-1-…` and `xoxe.xoxp-1-…`, whose bodies
// are opaque URL-safe Base64.
func xoxeAt(content []byte, start int) (detect.Token, bool) {
	rest := content[start+len("xoxe"):]
	kind, prefixLen := KindRefresh, len("-1-")
	switch {
	case hasPrefix(rest, "-1-"):
	case hasPrefix(rest, ".xoxb-1-"), hasPrefix(rest, ".xoxp-1-"):
		kind, prefixLen = KindConfig, len(".xoxb-1-")
	default:
		return detect.Token{}, false
	}
	pos := start + len("xoxe") + prefixLen
	l := detect.Span(content, pos, xoxeMax+1, isBase64URL)
	if l < xoxeMin || l > xoxeMax {
		return detect.Token{}, false
	}
	return detect.Token{Kind: kind, Value: string(content[start : pos+l]), Offset: start}, true
}

// webhookAt matches the three incoming webhook shapes:
//
//	/services/T…/B…/<24 alphanumerics>
//	/workflows/T…/A…/<digits>/<secret>
//	/triggers/T…/<digits>/<secret>
func webhookAt(content []byte, start int) (detect.Token, bool) {
	pos := start + len(hooksOrigin) + 1
	rest := content[pos:]
	var route string
	for _, r := range []string{"services/", "workflows/", "triggers/"} {
		if hasPrefix(rest, r) {
			route = r
			break
		}
	}
	if route == "" {
		return detect.Token{}, false
	}
	pos += len(route)
	team, pos, ok := slug(content, pos, 'T')
	if !ok {
		return detect.Token{}, false
	}
	attribution := "team " + team
	var end int
	if route == "services/" {
		bot, next, ok := slug(content, pos, 'B')
		if !ok {
			return detect.Token{}, false
		}
		attribution += ", bot " + bot
		if end, ok = secret(content, next, webhookSecretLen, webhookSecretLen, detect.IsAlnum); !ok {
			return detect.Token{}, false
		}
	} else {
		// One to two more id segments, then the secret.
		segments := 0
		for segments < 2 {
			l := detect.Span(content, pos, pathSecretMax+1, detect.IsAlnum)
			if l == 0 || pos+l >= len(content) || content[pos+l] != '/' {
				break
			}
			if segments == 0 && route == "workflows/" && content[pos] == 'A' {
				attribution += ", app " + string(content[pos:pos+l])
			}
			pos += l + 1
			segments++
		}
		if segments == 0 {
			return detect.Token{}, false
		}
		if end, ok = secret(content, pos, pathSecretMin, pathSecretMax, detect.IsAlnum); !ok {
			return detect.Token{}, false
		}
	}
	if end < len(content) && content[end] == '/' {
		return detect.Token{}, false
	}
	return detect.Token{Kind: KindWebhook, Value: string(content[start:end]), Offset: start, Attribution: attribution}, true
}

// slug reads a webhook id segment: the letter followed by 8 to 11
// alphanumerics and a slash. It returns the id and the position after the slash.
func slug(content []byte, pos int, letter byte) (string, int, bool) {
	if pos >= len(content) || content[pos] != letter {
		return "", 0, false
	}
	l := detect.Span(content, pos+1, slugMax+1, detect.IsAlnum)
	if l < slugMin || l > slugMax || pos+1+l >= len(content) || content[pos+1+l] != '/' {
		return "", 0, false
	}
	return string(content[pos : pos+1+l]), pos + 1 + l + 1, true
}

func hasPrefix(b []byte, prefix string) bool {
	return len(b) >= len(prefix) && string(b[:len(prefix)]) == prefix
}

func isUpperAlnum(c byte) bool {
	return detect.IsDigit(c) || (c >= 'A' && c <= 'Z')
}

func isBase64URL(c byte) bool {
	return detect.IsAlnum(c) || c == '-' || c == '_'
}
