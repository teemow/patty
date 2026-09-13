package azure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// TestSignSharedKey checks the signature against the string the storage
// documentation prescribes for a GET without a body: the verb, eleven
// empty standard header lines (Content-Length is empty for zero, Date is
// empty because x-ms-date is used), the x-ms headers sorted with a
// trailing newline each, and the resource with its query parameters.
func TestSignSharedKey(t *testing.T) {
	key := strings.Repeat("A", storageKeyBody) + "=="
	req, _ := http.NewRequest(http.MethodGet, "https://"+account+".blob.core.windows.net/?comp=list", nil)
	if err := signSharedKey(req, account, key, now); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("x-ms-date"); got != "Sun, 13 Sep 2026 12:00:00 GMT" {
		t.Errorf("x-ms-date %q", got)
	}
	want := "GET\n" + strings.Repeat("\n", 11) +
		"x-ms-date:Sun, 13 Sep 2026 12:00:00 GMT\n" +
		"x-ms-version:" + apiVersion + "\n" +
		"/" + account + "/\ncomp:list"
	if got := stringToSign(req, account); got != want {
		t.Errorf("string to sign:\n%q\nwant\n%q", got, want)
	}
	raw, _ := base64.StdEncoding.DecodeString(key)
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(want))
	if got, want := req.Header.Get("Authorization"), "SharedKey "+account+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("Authorization %q, want %q", got, want)
	}
	if err := signSharedKey(req, account, "not base64!", now); err == nil {
		t.Error("a key that is not base64 must not sign")
	}
}

// TestCanonicalizedResource covers the sorting and joining rules: parameter
// names lower-cased and sorted, several values of one name joined with
// commas, the account in front of the path.
func TestCanonicalizedResource(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://"+account+".blob.core.windows.net/container/blob%20name?restype=container&comp=list&include=metadata&include=deleted", nil)
	want := "/" + account + "/container/blob%20name\ncomp:list\ninclude:deleted,metadata\nrestype:container"
	if got := canonicalizedResource(req.URL, account); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	req.Header.Set("X-Ms-Version", apiVersion)
	req.Header.Set("x-ms-client-request-id", " abc ")
	if got, want := canonicalizedHeaders(req.Header), "x-ms-client-request-id:abc\nx-ms-version:"+apiVersion+"\n"; got != want {
		t.Errorf("headers %q, want %q", got, want)
	}
}
