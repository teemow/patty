package detect

import (
	"strings"
	"testing"
)

// classic builds a well-formed classic token from a 30-character random part.
func classic(prefix, random string) string {
	if len(random) != classicRandomLen {
		panic("random part must be 30 characters")
	}
	return prefix + random + Checksum(random)
}

const random30 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123"

func TestBase62KnownVector(t *testing.T) {
	// crc32("The quick brown fox jumps over the lazy dog") = 0x414FA339 = 1095738169
	// 1095738169 in base62 (0-9A-Za-z) is "1CoZdx"? Verified below by
	// arithmetic rather than a magic string, so the expectation is transparent.
	n := uint32(1095738169)
	got := base62(n)
	var back uint64
	for i := 0; i < len(got); i++ {
		back = back*62 + uint64(strings.IndexByte(base62Alphabet, got[i]))
	}
	if back != uint64(n) || len(got) != checksumLen {
		t.Fatalf("base62 round trip failed: %q -> %d", got, back)
	}
	if base62(0) != "000000" {
		t.Fatalf("zero must be left-padded, got %q", base62(0))
	}
	if Checksum("The quick brown fox jumps over the lazy dog") != got {
		t.Fatalf("Checksum must be base62(crc32 IEEE)")
	}
}

func TestFindClassicTokens(t *testing.T) {
	for letter, kind := range classicKinds {
		p := struct {
			prefix string
			kind   Kind
		}{"gh" + string(letter) + "_", kind}
		tok := classic(p.prefix, random30)
		content := []byte("line one\nexport TOKEN=\"" + tok + "\"\n")
		got := Find(content)
		if len(got) != 1 {
			t.Fatalf("%s: want 1 token, got %d", p.prefix, len(got))
		}
		if got[0].Kind != p.kind || got[0].Value != tok || got[0].Line != 2 || !got[0].ChecksumVerified {
			t.Fatalf("%s: unexpected token %+v", p.prefix, got[0])
		}
		if got[0].Offset != strings.Index(string(content), tok) {
			t.Fatalf("%s: wrong offset %d", p.prefix, got[0].Offset)
		}
	}
}

func TestFindRejectsBadChecksum(t *testing.T) {
	tok := classic("ghp_", random30)
	bad := tok[:len(tok)-1] + flip(tok[len(tok)-1])
	if got := Find([]byte("token: " + bad)); len(got) != 0 {
		t.Fatalf("token with wrong checksum must be rejected, got %+v", got)
	}
}

func TestFindRejectsWrongShape(t *testing.T) {
	tok := classic("ghp_", random30)
	cases := map[string]string{
		"truncated":      tok[:len(tok)-1],
		"trailing alnum": tok + "Z",
		"non-alnum body": "ghp_" + strings.Replace(random30, "C", "-", 1) + Checksum(random30),
		"prefix only":    "ghp_",
		"empty":          "",
	}
	for name, c := range cases {
		if got := Find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindAcceptsTokenAtBoundaries(t *testing.T) {
	tok := classic("gho_", random30)
	for _, c := range []string{tok, tok + "\n", "x-access-token:" + tok + "@github.com", "(" + tok + ")"} {
		if got := Find([]byte(c)); len(got) != 1 || got[0].Value != tok {
			t.Errorf("%q: want exactly the token, got %+v", c, got)
		}
	}
}

func TestFindFineGrained(t *testing.T) {
	id := strings.Repeat("A", fineGrainedIDLen)
	body := strings.Repeat("b", fineGrainedBodyLen-10) + "0123456789"
	tok := fineGrainedPrefix + id + "_" + body
	got := Find([]byte("a\nb\nc " + tok + " d"))
	if len(got) != 1 || got[0].Kind != KindFineGrained || got[0].Value != tok || got[0].Line != 3 || got[0].ChecksumVerified {
		t.Fatalf("unexpected result %+v", got)
	}
	for name, c := range map[string]string{
		"too short":       tok[:len(tok)-1],
		"trailing alnum":  tok + "x",
		"trailing _":      tok + "_",
		"missing sep":     fineGrainedPrefix + id + "X" + body,
		"non-alnum in id": fineGrainedPrefix + id[:5] + "-" + id[6:] + "_" + body,
	} {
		if got := Find([]byte(c)); len(got) != 0 {
			t.Errorf("%s: want no token, got %+v", name, got)
		}
	}
}

func TestFindMultipleSorted(t *testing.T) {
	a := classic("ghp_", random30)
	b := classic("ghs_", "0123456789abcdefghijABCDEFGHIJ")
	got := Find([]byte(b + "\n" + a + "\n" + b))
	if len(got) != 3 || got[0].Value != b || got[1].Value != a || got[2].Value != b {
		t.Fatalf("want [b a b] sorted by offset, got %+v", got)
	}
	if got[0].Line != 1 || got[1].Line != 2 || got[2].Line != 3 {
		t.Fatalf("wrong line numbers: %+v", got)
	}
}

func TestRedactAndFingerprint(t *testing.T) {
	tok := classic("ghp_", random30)
	r := Redact(tok)
	if !strings.HasPrefix(r, "ghp_AbCd") || !strings.HasSuffix(r, tok[len(tok)-4:]) || len(r) >= len(tok) {
		t.Fatalf("bad redaction %q", r)
	}
	if strings.Contains(r, random30[4:]) {
		t.Fatalf("redaction leaks the random part: %q", r)
	}
	if Redact("short") != "short" {
		t.Fatal("short values pass through")
	}
	fp := Fingerprint(tok)
	if len(fp) != 16 || fp != (Token{Value: tok}).Fingerprint() {
		t.Fatalf("bad fingerprint %q", fp)
	}
}

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func BenchmarkFind(b *testing.B) {
	content := []byte(strings.Repeat("some source code with light and night and ghpx_ in it\n", 20000))
	b.SetBytes(int64(len(content)))
	for b.Loop() {
		Find(content)
	}
}
