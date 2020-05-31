package encoding

import (
	"regexp"
	"unicode/utf8"
)

// IsAlphaNumeric returns true if string is only a-z, A-Z, 0-9 with optional extra characters.
func IsAlphaNumeric(s string, extra string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9` + extra + `]+$`).MatchString(s)
}

// IsASCII returns true if bytes are ASCII.
func IsASCII(b []byte) bool {
	isASCII := true
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
	}
	return isASCII
}

// HasUpper returns true if string has an uppercase character.
func HasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}
