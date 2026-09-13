package pagerduty

import (
	"strings"
	"testing"

	"github.com/teemow/patty/internal/detect"
)

var find = New().Find

const (
	generalBody = "AbCdEfGhIjKlMnOp-_"
	userBody    = "AbCdEfGhIjKl+/Mn-_"
	// hex32 is a routing key built from the hex alphabet; never a real one.
	hex32 = "0123456789abcdef" + "fedcba9876543210"
)

func general() string { return generalPrefix + generalBody }
func user() string    { return userPrefix + userBody }

func TestFindGeneralAccessKeyNeedsAMarker(t *testing.T) {
	key := general()
	if got := find([]byte("api_key = " + key + "\n")); len(got) != 0 {
		t.Fatalf("a y_ key without a PagerDuty marker is not reported, got %+v", got)
	}
	for _, marker := range []string{"PAGERDUTY_TOKEN=", "pd_api_key: ", "# sent to api.pagerduty.com\nkey=", "Authorization: Token token="} {
		content := []byte(marker + key + "\n")
		got := find(content)
		if len(got) != 1 || got[0].Kind != KindAPIKey || got[0].Value != key || got[0].ChecksumVerified || got[0].Offset != strings.Index(string(content), key) {
			t.Fatalf("%q: unexpected result %+v", marker, got)
		}
	}
}

func TestFindUserKeyOnShapeAlone(t *testing.T) {
	key := user()
	content := []byte("token: " + key + "\n")
	got := find(content)
	if len(got) != 1 || got[0].Kind != KindAPIKey || got[0].Value != key || got[0].Offset != strings.Index(string(content), key) {
		t.Fatalf("unexpected result %+v", got)
	}
	for _, c := range []string{key, "(" + key + ")", `"` + key + `"`, "x=" + key} {
		if got := find([]byte(c)); len(got) != 1 || got[0].Value != key {
			t.Errorf("%q: want exactly the key, got %+v", c, got)
		}
	}
}

func TestFindRejectsWrongAPIKeyShapes(t *testing.T) {
	for name, c := range map[string]string{
		"too short":            "pagerduty " + general()[:19],
		"trailing alnum":       "pagerduty " + general() + "x",
		"trailing plus":        "pagerduty " + general() + "+",
		"trailing padding":     user() + "=",
		"inside a word":        "pagerduty key" + general(),
		"inside base64":        "AQ/" + user(),
		"general with slash":   "pagerduty " + generalPrefix + strings.Replace(generalBody, "-", "/", 1),
		"prefix only":          "pagerduty y_ u+",
		"policy_ is not a key": "pagerduty policy_" + generalBody[2:],
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no key, got %+v", name, got)
		}
	}
}

const alertmanager = `global:
  resolve_timeout: 5m
route:
  receiver: pagerduty-critical
receivers:
  - name: pagerduty-critical
    pagerduty_configs:
      - routing_key: ` + hex32 + `
        severity: critical
  - name: pagerduty-legacy
    pagerduty_configs:
      - service_key: "` + "fedcba9876543210" + "0123456789abcdef" + `"
        routing_key_file: /etc/alertmanager/key
  - name: slack
    slack_configs:
      - channel: '#alerts'
`

func TestFindRoutingKeysInAlertmanagerConfig(t *testing.T) {
	got := find([]byte(alertmanager))
	if len(got) != 2 {
		t.Fatalf("want the two receivers' keys, got %+v", got)
	}
	if got[0].Kind != KindRoutingKey || got[0].Value != hex32 || got[0].Attribution != "routing_key of receiver pagerduty-critical in Alertmanager config" || got[0].ChecksumVerified {
		t.Fatalf("critical: %+v", got[0])
	}
	if got[0].Offset != strings.Index(alertmanager, hex32) {
		t.Fatalf("offset %d, want the value's", got[0].Offset)
	}
	if got[1].Attribution != "service_key of receiver pagerduty-legacy in Alertmanager config" {
		t.Fatalf("legacy: %+v", got[1])
	}
	// The same content inside a Kubernetes Secret is found by the registry
	// through the decoded value, once.
	registry := detect.NewRegistry(New())
	secret := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: alertmanager\nstringData:\n  alertmanager.yaml: |\n" + indent(alertmanager, "    ")
	got = registry.Find([]byte(secret))
	if len(got) != 2 || !strings.HasPrefix(got[0].Attribution, "in Secret alertmanager, key alertmanager.yaml (routing_key of receiver pagerduty-critical") {
		t.Fatalf("in a Secret: %+v", got)
	}
}

func TestFindRoutingKeysByConfigurationKey(t *testing.T) {
	for name, c := range map[string]struct{ content, attribution string }{
		"terraform": {`resource "pagerduty_service_integration" "am" {
  service         = pagerduty_service.example.id
  vendor          = data.pagerduty_vendor.alertmanager.id
  integration_key = "` + hex32 + `"
}`, "under integration_key"},
		"env":          {"PAGERDUTY_ROUTING_KEY=" + hex32 + "\n", "under PAGERDUTY_ROUTING_KEY"},
		"env pd":       {"export PD_ROUTING_KEY='" + hex32 + "'\n", "under PD_ROUTING_KEY"},
		"json":         {`{"pagerduty_routing_key": "` + hex32 + `", "other": 1}`, "under pagerduty_routing_key"},
		"yaml":         {"pagerduty:\n  routing_key: " + hex32 + "\n", "under routing_key"},
		"helm values":  {"alertmanager:\n  config:\n    receivers:\n    - name: pd\n      pagerduty_configs:\n      - service_key: " + hex32 + "\n", "service_key of receiver pd in Alertmanager config"},
		"spaced equal": {"integration_key   =   " + hex32, "under integration_key"},
	} {
		got := find([]byte(c.content))
		if len(got) != 1 || got[0].Kind != KindRoutingKey || got[0].Value != hex32 || got[0].Attribution != c.attribution || got[0].Offset != strings.Index(c.content, hex32) {
			t.Errorf("%s: unexpected result %+v", name, got)
		}
	}
}

func TestBareHexIsNotARoutingKey(t *testing.T) {
	for name, c := range map[string]string{
		"bare":             hex32,
		"other key":        "checksum: " + hex32,
		"md5 line":         hex32 + "  file.tar.gz",
		"routing_key_file": "routing_key_file: " + hex32,
		"upper case":       "routing_key: " + strings.ToUpper(hex32),
		"too long":         "routing_key: " + hex32 + "0",
		"too short":        "routing_key: " + hex32[1:],
		"not hex":          "routing_key: " + strings.Replace(hex32, "a", "g", 1),
		"path value":       "routing_key: /run/secrets/" + hex32,
	} {
		if got := find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no key, got %+v", name, got)
		}
	}
}

func TestKindsAreComplete(t *testing.T) {
	kinds := map[detect.Kind]bool{}
	for _, k := range New().Kinds() {
		kinds[k.Kind] = true
		if k.Revocable || k.Description == "" || k.RevokeNote == "" || k.AuditNote == "" {
			t.Errorf("%s: nothing here is revocable through the API and every kind carries the owner's procedure: %+v", k.Kind, k)
		}
	}
	if !kinds[KindAPIKey] || !kinds[KindRoutingKey] {
		t.Fatal("a kind is missing from Kinds")
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}

func BenchmarkFind(b *testing.B) {
	content := []byte(strings.Repeat("some source code with policy_ and key_ and you+me in it and a routing_key_file\n", 20000))
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		find(content)
	}
}
