package encoding

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// TrimSaltpack removes non base63 characters from a string.
func TrimSaltpack(msg string, allow []rune) string {
	charsOnly := func(r rune) rune {
		// 0-9, A-Z, a-z
		if (r >= 0x30 && r <= 0x39) || (r >= 0x41 && r <= 0x5A) || (r >= 0x61 && r <= 0x7A) {
			return r
		}
		for _, a := range allow {
			if r == a {
				return r
			}
		}
		return -1
	}
	return strings.Map(charsOnly, msg)
}

// EncodeSaltpack encodes bytes to saltpack message.
func EncodeSaltpack(b []byte, brand string) string {
	return saltpackStart(brand) + "\n" + encodeSaltpack(b) + "\n" + saltpackEnd(brand)
}

// DecodeSaltpack decodes saltpack message.
func DecodeSaltpack(msg string, isHTML bool) ([]byte, string, error) {
	s, brand := FindSaltpack(msg, isHTML)
	if s == "" {
		return nil, "", nil
	}
	s = TrimSaltpack(s, nil)
	b, err := Decode(s, Base62)
	if err != nil {
		return nil, "", errors.Wrapf(err, "failed to decode saltpack message")
	}
	return b, brand, nil
}

func encodeSaltpack(b []byte) string {
	out := MustEncode(b, Base62)
	out = out + "."
	return BreakString(out, 15, 4)
}

func decodeSaltpack(s string) ([]byte, error) {
	s = TrimSaltpack(s, nil)
	return Decode(s, Base62)
}

// saltpackStart start of a saltpack message.
func saltpackStart(brand string) string {
	if brand == "" {
		return "BEGIN MESSAGE."
	}
	return fmt.Sprintf("BEGIN %s MESSAGE.", brand)
}

// saltpackEnd end of a saltpack message.
func saltpackEnd(brand string) string {
	if brand == "" {
		return "END MESSAGE."
	}
	return fmt.Sprintf("END %s MESSAGE.", brand)
}
