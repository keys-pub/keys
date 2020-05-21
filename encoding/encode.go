// Package encoding provides encoding and decoding of different formats like Base62, Saltpack, BIP39.
package encoding

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"

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

// NewEncoding returns an Encoding from a string.
func NewEncoding(s string) Encoding {
	enc, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return enc
}

// Parse returns an Encoding from a string.
func Parse(s string) (Encoding, error) {
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

// ParseOr returns an Encoding from a string, or if empty, a default.
func ParseOr(s string, d Encoding) (Encoding, error) {
	if s == "" {
		return d, nil
	}
	return Parse(s)
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

// MustDecode decodes or panics.
func MustDecode(s string, encoding Encoding) []byte {
	b, err := Decode(s, encoding)
	if err != nil {
		panic(err)
	}
	return b
}
