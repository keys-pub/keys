package keys

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/keybase/saltpack/encoding/basex"
	"github.com/pkg/errors"
)

// Encoding is an encoding for bytes to and from a string
type Encoding string

const (
	// NoEncoding ...
	NoEncoding Encoding = ""
	// Hex (Base16) encoding
	Hex Encoding = "base16"
	// Base32 encoding
	Base32 Encoding = "base32"
	// Base58 encoding
	Base58 Encoding = "base58"
	// Base62 encoding
	Base62 Encoding = "base62"
	// Base64 encoding (with padding)
	Base64 Encoding = "base64"
	// Saltpack encoding
	Saltpack Encoding = "saltpack"
	// BIP39 encoding
	BIP39 Encoding = "bip39"
)

// NewEncoding returns an Encoding from a string
func NewEncoding(s string) Encoding {
	enc, err := ParseEncoding(s)
	if err != nil {
		panic(err)
	}
	return enc
}

// ParseEncoding returns an Encoding from a string
func ParseEncoding(s string) (Encoding, error) {
	switch s {
	case string(Hex):
		return Hex, nil
	case string(Base32):
		return Base32, nil
	case string(Base58):
		return Base58, nil
	case string(Base62):
		return Base62, nil
	case string(Base64):
		return Base64, nil
	case string(Saltpack):
		return Saltpack, nil
	case string(BIP39):
		return BIP39, nil
	case string(NoEncoding):
		return NoEncoding, nil
	default:
		return NoEncoding, errors.Errorf("invalid encoding %s", s)
	}
}

// ParseEncodingOr returns an Encoding from a string, or if empty, a default
func ParseEncodingOr(s string, d Encoding) (Encoding, error) {
	if s == "" {
		return d, nil
	}
	return ParseEncoding(s)
}

// Encode encodes bytes to an Encoding.
func Encode(b []byte, encoding Encoding) (string, error) {
	switch encoding {
	case Base64:
		return base64.StdEncoding.EncodeToString(b), nil
	case Base62:
		return basex.Base62StdEncodingStrict.EncodeToString(b), nil
	case Base58:
		return basex.Base58StdEncodingStrict.EncodeToString(b), nil
	case Base32:
		return base32.StdEncoding.EncodeToString(b), nil
	case Hex:
		return hex.EncodeToString(b), nil
	case Saltpack:
		return encodeSaltpack(b), nil
	case BIP39:
		return BytesToPhrase(b)
	default:
		return "", errors.Errorf("unrecognized encoding")
	}
}

// MustEncode returns encoding or panics on error.
func MustEncode(b []byte, encoding Encoding) string {
	s, err := Encode(b, encoding)
	if err != nil {
		panic(err)
	}
	return s
}

// Decode decodes string to bytes using encoding
func Decode(s string, encoding Encoding) ([]byte, error) {
	switch encoding {
	case Base64:
		return base64.StdEncoding.DecodeString(s)
	case Base62:
		return basex.Base62StdEncodingStrict.DecodeString(s)
	case Base58:
		return basex.Base58StdEncodingStrict.DecodeString(s)
	case Base32:
		return base32.StdEncoding.DecodeString(s)
	case Hex:
		return hex.DecodeString(s)
	case Saltpack:
		return decodeSaltpack(s)
	case BIP39:
		b, err := PhraseToBytes(s, true)
		if err != nil {
			return nil, err
		}
		return b[:], nil
	default:
		return nil, errors.Errorf("unknown encoding")
	}
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

func trimMessage(msg string) string {
	base62Only := func(r rune) rune {
		// 0-9, A-Z, a-z
		if (r >= 0x30 && r <= 0x39) || (r >= 0x41 && r <= 0x5A) || (r >= 0x61 && r <= 0x7A) {
			return r
		}
		return -1
	}
	return strings.Map(base62Only, msg)
}

func encodeSaltpack(b []byte) string {
	out := MustEncode(b, Base62)
	out = out + "."
	return breakString(out, 15, 4)
}

func decodeSaltpack(s string) ([]byte, error) {
	s = trimMessage(s)
	return Decode(s, Base62)
}

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}
