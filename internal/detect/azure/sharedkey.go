package azure

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// apiVersion is the storage REST API version the signed request names.
const apiVersion = "2023-11-03"

// signSharedKey authorizes the request with the account key the way the
// storage service documents Shared Key: an HMAC-SHA256 over the verb, the
// standard headers, the canonicalized x-ms headers and the canonicalized
// resource, with the decoded key. The request gets its x-ms-date and
// x-ms-version headers here so the signature covers them.
func signSharedKey(req *http.Request, account, key string, now time.Time) error {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return errors.New("the key is not base64")
	}
	req.Header.Set("x-ms-date", now.UTC().Format(http.TimeFormat))
	req.Header.Set("x-ms-version", apiVersion)
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(stringToSign(req, account)))
	req.Header.Set("Authorization", "SharedKey "+account+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return nil
}

// stringToSign builds the Shared Key string for a request without a body:
// the verb, twelve standard header lines (Content-Length empty for none),
// the x-ms headers sorted, and the resource with its query parameters
// sorted.
func stringToSign(req *http.Request, account string) string {
	standard := []string{
		"Content-Encoding", "Content-Language", "Content-Length", "Content-MD5", "Content-Type",
		"Date", "If-Modified-Since", "If-Match", "If-None-Match", "If-Unmodified-Since", "Range",
	}
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteByte('\n')
	for _, h := range standard {
		if h != "Content-Length" && h != "Date" {
			b.WriteString(req.Header.Get(h))
		}
		b.WriteByte('\n')
	}
	b.WriteString(canonicalizedHeaders(req.Header))
	b.WriteString(canonicalizedResource(req.URL, account))
	return b.String()
}

func canonicalizedHeaders(header http.Header) string {
	var names []string
	for name := range header {
		if lower := strings.ToLower(name); strings.HasPrefix(lower, "x-ms-") {
			names = append(names, lower)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(strings.Join(header.Values(name), ",")))
		b.WriteByte('\n')
	}
	return b.String()
}

func canonicalizedResource(u *url.URL, account string) string {
	var b strings.Builder
	b.WriteString("/" + account + u.EscapedPath())
	q := u.Query()
	names := make([]string, 0, len(q))
	for name := range q {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	for _, name := range names {
		values := q[name]
		sort.Strings(values)
		b.WriteString("\n" + name + ":" + strings.Join(values, ","))
	}
	return b.String()
}
