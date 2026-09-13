package gitlab

import (
	"encoding/base64"
	"hash/crc32"
	"strconv"
	"strings"

	"github.com/teemow/patty/internal/detect"
)

// The routable token format, as GitLab's Authn::TokenField::Generator::
// RoutableToken builds it:
//
//	<prefix><base64url(random16 + payload + byte(len(payload)))>.<version>.<length><crc>
//
// where version is the token version in two base36 digits (`01`), length
// the base64 payload's length in two base36 digits, and crc the CRC32 of
// everything before it in seven base36 digits. The first iteration of the
// format had no version segment: `<prefix><base64>.<length><crc>`. Both
// are accepted; the checksum has to hold either way.
const (
	routableRandomLen         = 16
	routableB64Min            = 27
	routableB64Max            = 300
	routableVersionLen        = 2
	routableLengthLen         = 2
	routableCRCLen            = 7
	routableTail              = routableLengthLen + routableCRCLen
	routableVersionedTail     = routableVersionLen + 1 + routableTail
	routableMaxPayloadPerLine = 159
)

// routingKeys names the payload keys.
var routingKeys = map[byte]string{'c': "cell", 'g': "group", 'o': "organization", 'p': "project", 'u': "user", 't': "type"}

// routableAt matches a routable token body starting at body, after its
// prefix, and returns its end and the attribution its payload gives. The
// checksum covers the prefix too, so start is where the token begins.
func routableAt(content []byte, start, body int) (end int, attribution string, ok bool) {
	n := detect.Span(content, body, routableB64Max+1, isTokenByte)
	if n < routableB64Min || n > routableB64Max || body+n >= len(content) || content[body+n] != '.' {
		return 0, "", false
	}
	b64 := content[body : body+n]
	pos := body + n + 1
	lengthAt := pos
	if detect.Span(content, pos, routableVersionLen+1, isBase36) == routableVersionLen && pos+routableVersionLen < len(content) && content[pos+routableVersionLen] == '.' {
		lengthAt = pos + routableVersionLen + 1 // the versioned layout
	}
	end = lengthAt + routableTail
	if end > len(content) || !detect.All(content[lengthAt:end], isBase36) || isTokenByteAt(content, end) {
		return 0, "", false
	}
	if string(content[lengthAt:lengthAt+routableLengthLen]) != base36(uint64(n), routableLengthLen) {
		return 0, "", false
	}
	crcAt := end - routableCRCLen
	if string(content[crcAt:end]) != RoutableChecksum(string(content[start:crcAt])) {
		return 0, "", false
	}
	attribution, ok = decodePayload(string(b64))
	if !ok {
		return 0, "", false
	}
	return end, attribution, true
}

// RoutableChecksum computes the seven base36 digits GitLab appends to a
// routable token: the CRC32 (IEEE) of everything before them. Exported so
// callers and tests can construct well-formed tokens without hard-coding
// any.
func RoutableChecksum(encoded string) string {
	return base36(uint64(crc32.ChecksumIEEE([]byte(encoded))), routableCRCLen)
}

// RoutableLength renders a base64 payload's length the way the token
// carries it.
func RoutableLength(n int) string {
	return base36(uint64(n), routableLengthLen)
}

// decodePayload reads the routing payload out of the base64 part: sixteen
// random bytes, `key:value` lines, and a final byte holding the payload's
// length. Integer values are base36.
func decodePayload(b64 string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) < routableRandomLen+2 {
		return "", false
	}
	size := int(raw[len(raw)-1])
	if size == 0 || size > routableMaxPayloadPerLine || routableRandomLen+size+1 != len(raw) {
		return "", false
	}
	var parts []string
	for _, line := range strings.Split(string(raw[routableRandomLen:routableRandomLen+size]), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || len(key) != 1 || value == "" {
			return "", false
		}
		name, known := routingKeys[key[0]]
		if !known {
			return "", false
		}
		if key[0] != 't' {
			n, err := strconv.ParseUint(value, 36, 64)
			if err != nil {
				return "", false
			}
			value = strconv.FormatUint(n, 10)
		}
		parts = append(parts, name+" "+value)
	}
	return strings.Join(parts, ", "), true
}

func base36(n uint64, width int) string {
	s := strconv.FormatUint(n, 36)
	if len(s) < width {
		s = strings.Repeat("0", width-len(s)) + s
	}
	return s
}

func isBase36(c byte) bool { return detect.IsDigit(c) || (c >= 'a' && c <= 'z') }
