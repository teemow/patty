package azure

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/teemow/patty/internal/detect"
)

// Every fixture is assembled at runtime so no credential-shaped literal is
// committed.
const (
	tenant  = "11111111-2222-3333-4444-555555555555"
	client  = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	account = "examplestorage"
)

var now = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

func provider() *Provider {
	p := New()
	p.now = func() time.Time { return now }
	return p
}

var find = provider().Find

// clientSecret builds a secret of the current 40-character shape: three
// characters, a digit, `Q~`, 34 more.
func clientSecret(fill string) string {
	return "abc" + "8" + secretAnchor + strings.Repeat(fill, secretBodyMax)[:secretBodyMax]
}

// storageKey is 64 bytes of base64, the shape of an account key, built
// from a repeated pattern.
func storageKey(fill byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(fill)+"k3y", 16)))
}

// sasURL is a blob URL with a signature that expires at the given time.
func sasURL(host, path, expires, sig string) string {
	return "https://" + host + path + "?sv=2022-11-02&ss=b&srt=sco&sp=rwdlacx&se=" + expires + "&st=2026-01-01T00%3A00%3A00Z&spr=https&sig=" + sig
}

func TestFindClientSecret(t *testing.T) {
	secret := clientSecret("xY.-_")
	for name, content := range map[string]string{
		"env":         "ARM_TENANT_ID=" + tenant + "\nARM_CLIENT_ID=" + client + "\nARM_CLIENT_SECRET=" + secret + "\n",
		"env quoted":  "export AZURE_CLIENT_SECRET='" + secret + "'\nexport AZURE_TENANT_ID=\"" + tenant + "\"\nexport AZURE_CLIENT_ID=\"" + client + "\"\n",
		"yaml":        "azure:\n  tenantId: " + tenant + "\n  clientId: " + client + "\n  clientSecret: " + secret + "\n",
		"terraform":   "provider \"azurerm\" {\n  tenant_id       = \"" + tenant + "\"\n  client_id       = \"" + client + "\"\n  client_secret   = \"" + secret + "\"\n}\n",
		"create-rbac": `{"appId": "` + client + `", "displayName": "deploy", "password": "` + secret + `", "tenant": "` + tenant + `"}`,
		"sdk-auth":    `{"clientId":"` + client + `","clientSecret":"` + secret + `","subscriptionId":"99999999-8888-7777-6666-555555555555","tenantId":"` + tenant + `"}`,
		"authority":   "authority: https://login.microsoftonline.com/" + tenant + "\napplicationId: " + client + "\nsecret: " + secret + "\n",
	} {
		found := find([]byte(content))
		if len(found) != 1 {
			t.Fatalf("%s: found %d tokens, want 1: %+v", name, len(found), found)
		}
		tok := found[0]
		if tok.Kind != KindClientSecret || tok.Value != secret || tok.ChecksumVerified {
			t.Errorf("%s: %+v", name, tok)
		}
		if tok.Attribution != "app "+client+" in tenant "+tenant {
			t.Errorf("%s: attribution %q", name, tok.Attribution)
		}
		if pr := decodePrincipal(tok); pr.Tenant != tenant || pr.Client != client {
			t.Errorf("%s: principal %+v", name, pr)
		}
		if strings.Index(content, secret) != tok.Offset {
			t.Errorf("%s: offset %d", name, tok.Offset)
		}
	}
}

func TestFindClientSecretPartial(t *testing.T) {
	secret := clientSecret("Ab1")
	for name, tc := range map[string]struct {
		content, attribution string
	}{
		"nothing":      {"password: " + secret + "\n", "tenant and client id not found nearby"},
		"tenant only":  {"AZURE_TENANT_ID=" + tenant + "\nAZURE_CLIENT_SECRET=" + secret + "\n", "tenant " + tenant + ", client id not found nearby"},
		"client only":  {"AZURE_CLIENT_ID=" + client + "\nAZURE_CLIENT_SECRET=" + secret + "\n", "app " + client + ", tenant id not found nearby"},
		"guid too far": {"tenant: " + strings.Repeat("x", guidWindow+1) + tenant + "\nsecret: " + secret + "\n", "tenant and client id not found nearby"},
		// The subscription id is a GUID too, but it stands behind its own
		// keyword; only the ids behind tenant and client keywords count.
		"subscription": {"subscriptionId: 99999999-8888-7777-6666-555555555555\nsecret: " + secret + "\n", "tenant and client id not found nearby"},
	} {
		found := find([]byte(tc.content))
		if len(found) != 1 || found[0].Attribution != tc.attribution {
			t.Errorf("%s: %+v", name, found)
		}
	}
	// Two principals in one file: each secret gets the ids closest to it.
	other := clientSecret("Zz9")
	otherTenant, otherClient := "22222222-3333-4444-5555-666666666666", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
	content := "[prod]\ntenant_id = " + tenant + "\nclient_id = " + client + "\nclient_secret = " + secret + "\n\n[staging]\ntenant_id = " + otherTenant + "\nclient_id = " + otherClient + "\nclient_secret = " + other + "\n"
	found := find([]byte(content))
	if len(found) != 2 {
		t.Fatalf("two principals: %+v", found)
	}
	if pr := decodePrincipal(found[0]); pr.Tenant != tenant || pr.Client != client {
		t.Errorf("first secret paired with %+v", pr)
	}
	if pr := decodePrincipal(found[1]); pr.Tenant != otherTenant || pr.Client != otherClient {
		t.Errorf("second secret paired with %+v", pr)
	}
}

func TestFindClientSecretNearMisses(t *testing.T) {
	body := strings.Repeat("x", 34)
	for name, content := range map[string]string{
		"no digit before":  "abcd" + secretAnchor + body,
		"body too short":   "abc8" + secretAnchor + strings.Repeat("x", secretBodyMin-1),
		"body too long":    "abc8" + secretAnchor + strings.Repeat("x", secretBodyMax+1),
		"in a word":        "xabc8" + secretAnchor + body,
		"head alphabet":    "a-c8" + secretAnchor + body,
		"anchor at start":  secretAnchor + body,
		"anchor elsewhere": "ab8" + secretAnchor + body,
		"prose":            "the secret has Q~ at the fifth position",
	} {
		if found := find([]byte(content)); len(found) != 0 {
			t.Errorf("%s: found %+v", name, found)
		}
	}
	// A dot right after the secret is punctuation.
	secret := clientSecret("Ab1")
	if found := find([]byte("The secret is " + secret + ".\n")); len(found) != 1 || found[0].Value != secret {
		t.Errorf("secret before a full stop: %+v", found)
	}
}

func TestFindStorageKey(t *testing.T) {
	key := storageKey('a')
	for name, content := range map[string]string{
		"connection string":          "AZURE_STORAGE_CONNECTION_STRING=DefaultEndpointsProtocol=https;AccountName=" + account + ";AccountKey=" + key + ";EndpointSuffix=core.windows.net\n",
		"connection string reversed": "conn: \"DefaultEndpointsProtocol=https;AccountKey=" + key + ";AccountName=" + account + ";EndpointSuffix=core.windows.net\"\n",
		"env":                        "AZURE_STORAGE_ACCOUNT=" + account + "\nAZURE_STORAGE_KEY=" + key + "\n",
		"env name":                   "export AZURE_STORAGE_ACCOUNT_NAME=\"" + account + "\"\nexport AZURE_STORAGE_ACCOUNT_KEY=\"" + key + "\"\n",
		"blob host":                  "url: https://" + account + ".blob.core.windows.net/container\nkey: " + key + "\n",
		"dfs host":                   "path: abfss://data@" + account + ".dfs.core.windows.net/\nfs.azure.account.key: " + key + "\n",
		"terraform":                  "storage_account_name = \"" + account + "\"\nstorage_account_key  = \"" + key + "\"\n",
		"yaml":                       "accountName: " + account + "\naccountKey: " + key + "\n",
		"json":                       `{"accountName": "` + account + `", "accountKey": "` + key + `"}`,
	} {
		found := find([]byte(content))
		if len(found) != 1 {
			t.Fatalf("%s: found %d tokens, want 1: %+v", name, len(found), found)
		}
		tok := found[0]
		if tok.Kind != KindStorageAccountKey || tok.Value != key || tok.Secret != account || tok.Attribution != "storage account "+account {
			t.Errorf("%s: %+v", name, tok)
		}
		if strings.Index(content, key) != tok.Offset {
			t.Errorf("%s: offset %d", name, tok.Offset)
		}
	}
	// Two accounts in one file: each key gets the name closest to it.
	other, otherKey := "otherstorage", storageKey('b')
	content := "prod:\n  storageAccount: " + account + "\n  key: " + key + "\nstaging:\n  storageAccount: " + other + "\n  key: " + otherKey + "\n"
	found := find([]byte(content))
	if len(found) != 2 || found[0].Secret != account || found[1].Secret != other {
		t.Errorf("two accounts: %+v", found)
	}
}

func TestFindStorageKeyUnpaired(t *testing.T) {
	key := storageKey('c')
	for name, content := range map[string]string{
		"alone":               key + "\n",
		"named key only":      "AZURE_STORAGE_KEY=" + key + "\n",
		"cosmos":              "https://exampledb.documents.azure.com:443/\nkey: " + key + "\n",
		"name too short":      "AZURE_STORAGE_ACCOUNT=ab\nAZURE_STORAGE_KEY=" + key + "\n",
		"name upper case":     "AZURE_STORAGE_ACCOUNT=MyStorage\nAZURE_STORAGE_KEY=" + key + "\n",
		"longer base64":       "AZURE_STORAGE_ACCOUNT=" + account + "\nkey: A" + key + "\n",
		"more padding":        "AZURE_STORAGE_ACCOUNT=" + account + "\nkey: " + key + "=\n",
		"certificate":         "AZURE_STORAGE_ACCOUNT=" + account + "\n-----BEGIN CERTIFICATE-----\n" + strings.Repeat("MIIC"+strings.Repeat("A", 60)+"\n", 5) + "MIIC" + strings.Repeat("A", 40) + "==\n-----END CERTIFICATE-----\n",
		"equality operator":   "if a == b {\n\tstorage_account = \"" + account + "\"\n}\n",
		"keyword names a key": "storage_account_key = \"" + key + "\"\n",
	} {
		if found := find([]byte(content)); len(found) != 0 {
			t.Errorf("%s: found %+v", name, found)
		}
	}
}

func TestFindSAS(t *testing.T) {
	sig := "abc%2Fdef%2Bghi%3D"
	live := sasURL(account+".blob.core.windows.net", "/backups/db.bak", "2030-01-01T00%3A00%3A00Z", sig)
	found := find([]byte("url: " + live + "\n"))
	if len(found) != 1 {
		t.Fatalf("live URL: %+v", found)
	}
	tok := found[0]
	if tok.Kind != KindSASToken || tok.Value != "abc/def+ghi=" || tok.Secret != live || tok.Offset != len("url: ") {
		t.Errorf("live URL: %+v", tok)
	}
	if tok.Attribution != "resource "+account+".blob.core.windows.net/backups/db.bak, permissions rwdlacx, expires 2030-01-01" {
		t.Errorf("attribution %q", tok.Attribution)
	}
	expired := sasURL(account+".blob.core.windows.net", "/backups", "2024-06-30", sig)
	found = find([]byte("<a href=\"" + expired + "\">download</a>"))
	if len(found) != 1 || !strings.HasSuffix(found[0].Attribution, "expired 2024-06-30") {
		t.Errorf("expired URL: %+v", found)
	}
	// A bare token, with or without its question mark, has no resource.
	bare := "sv=2022-11-02&sr=c&sp=rl&se=2030-01-01T00%3A00Z&sig=" + sig
	for _, content := range []string{"AZURE_STORAGE_SAS_TOKEN=" + bare + "\n", "sas: \"?" + bare + "\"\n"} {
		found = find([]byte(content))
		if len(found) != 1 || found[0].Value != "abc/def+ghi=" || found[0].Attribution != "bare token, resource unknown, permissions rl, expires 2030-01-01" {
			t.Errorf("bare token %q: %+v", content, found)
		}
		if s, ok := parseSignature(found[0].Secret); !ok || s.Resource != "" {
			t.Errorf("bare token %q: secret %q parses to %+v", content, found[0].Secret, s)
		}
	}
	// A trailing full stop is punctuation, the signature is not cut short.
	found = find([]byte("See " + live + ".\n"))
	if len(found) != 1 || found[0].Secret != live {
		t.Errorf("URL before a full stop: %+v", found)
	}
}

func TestFindSASNearMisses(t *testing.T) {
	for name, content := range map[string]string{
		"no sv":      "https://" + account + ".blob.core.windows.net/x?se=2030-01-01&sig=abc",
		"no se":      "https://" + account + ".blob.core.windows.net/x?sv=2022-11-02&sig=abc",
		"no sig":     "https://" + account + ".blob.core.windows.net/x?sv=2022-11-02&se=2030-01-01",
		"other sig":  "https://example.com/cb?hsig=abc&sv=1&se=2",
		"aws":        "https://bucket.s3.amazonaws.com/x?X-Amz-Signature=abc&X-Amz-Date=2030",
		"empty sig":  "https://" + account + ".blob.core.windows.net/x?sv=2022-11-02&se=2030-01-01&sig=",
		"bad escape": "sv=2022-11-02&se=2030-01-01&sig=%zz",
	} {
		if found := find([]byte(content)); len(found) != 0 {
			t.Errorf("%s: found %+v", name, found)
		}
	}
}

func TestAllKindsTogether(t *testing.T) {
	secret, key := clientSecret("Ab1"), storageKey('d')
	sas := sasURL(account+".blob.core.windows.net", "/c/b", "2030-01-01", "s1g")
	content := "AZURE_TENANT_ID=" + tenant + "\nAZURE_CLIENT_ID=" + client + "\nAZURE_CLIENT_SECRET=" + secret + "\nAZURE_STORAGE_ACCOUNT=" + account + "\nAZURE_STORAGE_KEY=" + key + "\nBACKUP_URL=" + sas + "\n"
	found := find([]byte(content))
	kinds := map[detect.Kind]string{}
	for _, tok := range found {
		kinds[tok.Kind] = tok.Value
	}
	if len(found) != 3 || kinds[KindClientSecret] != secret || kinds[KindStorageAccountKey] != key || kinds[KindSASToken] != "s1g" {
		t.Errorf("found %+v", found)
	}
	for _, tok := range found {
		if detect.Redact(tok.Value) == tok.Value && len(tok.Value) > 13 {
			t.Errorf("%s is shown in full", tok.Kind)
		}
	}
}

func TestPrincipalEncoding(t *testing.T) {
	if (principal{}).encode() != "" {
		t.Error("an empty principal must encode to nothing")
	}
	tok := detect.Token{Secret: principal{Tenant: tenant}.encode()}
	if decodePrincipal(tok).Tenant != tenant {
		t.Error("round trip lost the tenant")
	}
}

// finishes runs fn and fails the test when it has not returned within the
// limit: a scan that never returns is worse than a wrong answer.
func finishes(t *testing.T, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("did not finish within %v", limit)
	}
}

// lockfile builds content shaped like a yarn.lock: n integrity hashes of
// 86 base64 characters and `==`, which is exactly the shape of a storage
// account key.
func lockfile(n int) string {
	var b strings.Builder
	for i := range n {
		sum := sha512.Sum512([]byte(strconv.Itoa(i)))
		fmt.Fprintf(&b, "\"pkg-%d@^1.0.0\":\n  version \"1.0.%d\"\n  integrity sha512-%s\n\n", i, i, base64.StdEncoding.EncodeToString(sum[:]))
	}
	return b.String()
}

func TestFindStorageKeyAmongHashes(t *testing.T) {
	// Every hash is a key candidate that has to be paired with an account
	// name; scanning the whole file again for each took seconds per
	// megabyte. The names are gathered once, and a lockfile names none.
	content := []byte(lockfile(20000))
	var found []detect.Token
	finishes(t, 10*time.Second, func() { found = find(content) })
	if len(found) != 0 {
		t.Errorf("found %d tokens in a lockfile, want none", len(found))
	}
}

func TestFindSASInMinifiedScript(t *testing.T) {
	// A parameter name written as a property (`e.sig=`) has no separator
	// in front of it and stands once in its span; the search for the start
	// of a bare token used to loop on it forever.
	for name, content := range map[string]string{
		"property":     "var e={};e.sig=t,e.sp=r,e.se=n;",
		"only sig":     "x.sig=1",
		"sig at start": "sig=1",
	} {
		var found []detect.Token
		finishes(t, 10*time.Second, func() { found = find([]byte(content)) })
		if len(found) != 0 {
			t.Errorf("%s: found %+v", name, found)
		}
	}
}

func TestQueryStart(t *testing.T) {
	for raw, want := range map[string]int{
		"sv=1&se=2&sig=3":       0,
		"TOKEN=sv=1&se=2&sig=3": 6,
		"?sv=1&sig=3":           1,
		"e.sig=t":               0,
		"x.sp=1&sig=y":          7,
		"nothing here":          0,
	} {
		if got := queryStart(raw); got != want {
			t.Errorf("queryStart(%q) = %d, want %d", raw, got, want)
		}
	}
}

func BenchmarkFindLockfile(b *testing.B) {
	content := []byte(lockfile(10000))
	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	for b.Loop() {
		find(content)
	}
}
