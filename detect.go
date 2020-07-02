package keys

import (
	"strings"
	"unicode/utf8"
)

// DetectEncoding tries to find out what encoding the bytes are.
// Returns bytes which may be different from input (for example, if whitespace is stripped).
func DetectEncoding(b []byte) ([]byte, Encoding) {
	if !utf8.Valid(b) {
		return b, UnknownEncoding
	}

	s := strings.TrimSpace(string(b))

	typ := UnknownEncoding

	if _, err := ParseID(s); err == nil {
		typ = IDEncoding
	} else if len(s) < 100 && (strings.HasPrefix(s, "kex1") || strings.HasPrefix(s, "kbx1")) {
		typ = IDEncoding
	} else if strings.Contains(s, "BEGIN ") && strings.Contains(s, " MESSAGE") {
		typ = SaltpackEncoding
	} else if strings.HasPrefix(s, "-----BEGIN ") {
		typ = SSHEncoding
	} else if strings.HasPrefix(s, "ssh-") {
		typ = SSHEncoding
	}

	return []byte(s), typ

}
