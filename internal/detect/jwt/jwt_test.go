package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// mint signs a token at runtime with a throwaway key, so no token-shaped
// literal is committed and the signature is real but unknown to anyone.
func mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	signing := enc(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestDecode(t *testing.T) {
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	tok := mint(t, map[string]any{"iss": "https://issuer.example.com", "sub": "system:serviceaccount:ns:sa", "aud": []string{"api", "vault"}, "exp": exp.Unix(), "iat": 1700000000, "kubernetes.io": map[string]any{"namespace": "ns"}})
	c, ok := Decode(tok)
	if !ok {
		t.Fatal("a signed token must decode")
	}
	if c.Issuer != "https://issuer.example.com" || c.Subject != "system:serviceaccount:ns:sa" || strings.Join(c.Audience, ",") != "api,vault" {
		t.Fatalf("registered claims: %+v", c)
	}
	if !c.Expires.Equal(exp) || c.IssuedAt.Unix() != 1700000000 || c.Expired(time.Now()) || !c.Expired(exp.Add(time.Second)) {
		t.Fatalf("times: %+v", c)
	}
	if c.Header["alg"] != "HS256" || c.Object("kubernetes.io")["namespace"] != "ns" || c.String("missing") != "" || c.Object("missing") != nil {
		t.Fatalf("raw access: %+v", c)
	}
	single, _ := Decode(mint(t, map[string]any{"aud": "one"}))
	if len(single.Audience) != 1 || single.Audience[0] != "one" || !single.Expires.IsZero() {
		t.Fatalf("string audience: %+v", single)
	}
}

func TestDecodeRejectsNonTokens(t *testing.T) {
	tok := mint(t, map[string]any{"iss": "x"})
	parts := strings.Split(tok, ".")
	for name, s := range map[string]string{
		"two parts":      parts[0] + "." + parts[1],
		"no signature":   parts[0] + "." + parts[1] + ".",
		"header not b64": "!!!." + parts[1] + "." + parts[2],
		"claims array":   parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + "." + parts[2],
		"empty":          "",
	} {
		if _, ok := Decode(s); ok {
			t.Errorf("%s must not decode", name)
		}
	}
}

func TestFindIsWordBounded(t *testing.T) {
	tok := mint(t, map[string]any{"iss": "kubernetes/serviceaccount"})
	content := "TOKEN=" + tok + "\nAuthorization: Bearer " + tok + "\nbroken: " + Prefix + "AAAA.oops\nglued: AAAA" + tok + "\nurl: https://example.com/?t=" + tok + "&x=1\n"
	got := Find([]byte(content))
	if len(got) != 3 {
		t.Fatalf("want the three standalone tokens, got %d: %+v", len(got), got)
	}
	for _, c := range got {
		if c.Value != tok || c.Claims.Issuer != "kubernetes/serviceaccount" {
			t.Errorf("candidate %+v", c)
		}
	}
	if got[0].Offset != len("TOKEN=") {
		t.Errorf("offset %d", got[0].Offset)
	}
	if Find([]byte("nothing here")) != nil {
		t.Error("no candidates must be nil")
	}
}
