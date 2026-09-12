package slack

import (
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

// Every test token is assembled at runtime so no token-shaped literal is
// committed.
var (
	teamNum = "1234567890"
	botNum  = "1234567890123"
	userNum = "9876543210"
	teamID  = "T" + "0123ABCD"
	botID   = "B" + "0123ABCDEF"
	appID   = "A" + "0123ABCDE"
	hex32   = strings.Repeat("0123456789abcdef", 2)
	hex64   = strings.Repeat("0123456789abcdef", 4)
	alnum24 = "AbCdEfGhIjKlMnOpQrStUvWx"
	base64s = strings.Repeat("Mi0yLTM1MDIzMz", 5) + "-_ab"
)

func bot() string     { return "xoxb-" + teamNum + "-" + botNum + "-" + alnum24 }
func user() string    { return "xoxp-" + teamNum + "-" + userNum + "-" + botNum + "-" + hex32 }
func app() string     { return "xapp-1-" + appID + "-" + teamNum + "-" + hex64 }
func refresh() string { return "xoxe-1-" + base64s }
func config() string  { return "xoxe.xoxp-1-" + base64s }
func webhook() string { return hooksOrigin + "/services/" + teamID + "/" + botID + "/" + alnum24 }

var find = New().Find

func TestFindEveryFamily(t *testing.T) {
	cases := []struct {
		name, value string
		kind        detect.Kind
		attribution string
	}{
		{"bot", bot(), KindBot, "team " + teamNum + ", bot " + botNum},
		{"user hex tail", user(), KindUser, "team " + teamNum + ", user " + userNum},
		{"user alnum tail", "xoxp-" + teamNum + "-" + userNum + "-" + botNum + "-" + strings.Repeat("Ab", 15), KindUser, "team " + teamNum + ", user " + userNum},
		{"app", app(), KindApp, "app " + appID},
		{"refresh", refresh(), KindRefresh, ""},
		{"config bot", "xoxe.xoxb-1-" + base64s, KindConfig, ""},
		{"config user", config(), KindConfig, ""},
		{"webhook", webhook(), KindWebhook, "team " + teamID + ", bot " + botID},
		{"workflow webhook", hooksOrigin + "/workflows/" + teamID + "/" + appID + "/123456789012345/" + alnum24 + "abcd", KindWebhook, "team " + teamID + ", app " + appID},
		{"trigger webhook", hooksOrigin + "/triggers/" + teamID + "/1234567890123/" + alnum24 + hex32, KindWebhook, "team " + teamID},
	}
	for _, c := range cases {
		for _, wrap := range []string{"%s", "token=%s\n", "\"%s\"", "Bearer %s;", "curl -X POST %s -d @body.json"} {
			content := strings.Replace(wrap, "%s", c.value, 1)
			got := find([]byte(content))
			if len(got) != 1 {
				t.Errorf("%s in %q: want 1 token, got %+v", c.name, wrap, got)
				continue
			}
			if got[0].Kind != c.kind || got[0].Value != c.value || got[0].Attribution != c.attribution || got[0].ChecksumVerified {
				t.Errorf("%s: unexpected %+v", c.name, got[0])
			}
			if got[0].Offset != strings.Index(content, c.value) {
				t.Errorf("%s: wrong offset %d", c.name, got[0].Offset)
			}
		}
	}
}

func TestFindRejectsWrongShapes(t *testing.T) {
	cases := map[string]string{
		"bot short team":         "xoxb-123456789-" + botNum + "-" + alnum24,
		"bot long bot id":        "xoxb-" + teamNum + "-12345678901234-" + alnum24,
		"bot short secret":       bot()[:len(bot())-1],
		"bot long secret":        bot() + "Z",
		"bot letters in id":      "xoxb-" + teamNum[:5] + "a" + teamNum[6:] + "-" + botNum + "-" + alnum24,
		"user two groups":        "xoxp-" + teamNum + "-" + userNum + "-" + hex32,
		"user short tail":        user()[:len(user())-5],
		"user long tail":         user() + "abc",
		"app lowercase id":       "xapp-1-A" + "0123abcde-" + teamNum + "-" + hex64,
		"app no A":               "xapp-1-" + "B0123ABCDE-" + teamNum + "-" + hex64,
		"app non-hex secret":     "xapp-1-" + appID + "-" + teamNum + "-" + strings.Repeat("g", 64),
		"app short secret":       app()[:len(app())-1],
		"refresh too short":      "xoxe-1-" + base64s[:20],
		"xoxe other":             "xoxe-2-" + base64s,
		"webhook short team":     hooksOrigin + "/services/T0123/" + botID + "/" + alnum24,
		"webhook no B":           hooksOrigin + "/services/" + teamID + "/" + appID + "/" + alnum24,
		"webhook short secret":   webhook()[:len(webhook())-1],
		"webhook long secret":    webhook() + "a",
		"webhook trailing slash": webhook() + "/x",
		"webhook other route":    hooksOrigin + "/commands/" + teamID + "/" + botID + "/" + alnum24,
		"workflow no segments":   hooksOrigin + "/workflows/" + teamID + "/" + alnum24,
		"prefix only":            "xoxb- xoxp- xapp-1- xoxe " + hooksOrigin + "/",
		"prose":                  "the xoxb-prefix marks bot tokens",
	}
	for name, c := range cases {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindDoesNotSplitRotatingTokens(t *testing.T) {
	// The xoxb- inside xoxe.xoxb-1- must not be reported as a second token.
	got := find([]byte("xoxe.xoxb-1-" + base64s))
	if len(got) != 1 || got[0].Kind != KindConfig {
		t.Fatalf("want one config token, got %+v", got)
	}
}

func TestFindMultiple(t *testing.T) {
	content := []byte(bot() + "\n" + webhook() + "\n" + user())
	got := find(content)
	if len(got) != 3 {
		t.Fatalf("want 3 tokens, got %+v", got)
	}
}

func TestKindsAreComplete(t *testing.T) {
	kinds := map[detect.Kind]detect.KindInfo{}
	for _, k := range New().Kinds() {
		kinds[k.Kind] = k
		if k.RevokePage == "" || k.Description == "" {
			t.Errorf("%s: incomplete %+v", k.Kind, k)
		}
	}
	for kind, revocable := range map[detect.Kind]bool{KindBot: true, KindUser: true, KindRefresh: true, KindApp: false, KindConfig: false, KindWebhook: false} {
		k, ok := kinds[kind]
		if !ok {
			t.Errorf("%s missing from Kinds", kind)
		}
		if k.Revocable != revocable {
			t.Errorf("%s: Revocable = %v", kind, k.Revocable)
		}
		if !revocable && k.RevokeNote == "" {
			t.Errorf("%s: an unrevocable kind needs a note on what to do instead", kind)
		}
	}
}

func TestRedactKeepsWebhookIDs(t *testing.T) {
	r := detect.Redact(webhook())
	if !strings.HasPrefix(r, hooksOrigin+"/services/"+teamID+"/"+botID+"/") || strings.Contains(r, alnum24) {
		t.Fatalf("bad redaction %q", r)
	}
}

func BenchmarkFind(b *testing.B) {
	content := []byte(strings.Repeat("some source code mentioning slack and xoxb and hooks.slack.com in prose\n", 20000))
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		find(content)
	}
}
