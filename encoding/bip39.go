package encoding

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
)

// ErrInvalidPhrase if phrase is invalid.
type ErrInvalidPhrase struct {
	cause error
}

// ErrInvalidBIP39Input if invalid number of bytes for encoding.
var ErrInvalidBIP39Input = errors.New("bip39 only accepts 16, 20, 24, 28, 32 bytes")

func (e ErrInvalidPhrase) Error() string {
	return "invalid phrase"
}

// Cause for ErrInvalidPhrase
func (e ErrInvalidPhrase) Cause() error {
	return e.cause
}

// BytesToPhrase returns a phrase for bytes
func BytesToPhrase(b []byte) (string, error) {
	out, err := bip39.NewMnemonic(b)
	if err != nil {
		if err == bip39.ErrEntropyLengthInvalid {
			return "", ErrInvalidBIP39Input
		}
		return "", err
	}
	return out, nil
}

// PhraseToBytes decodes a bip39 mnemonic into bytes
func PhraseToBytes(phrase string, sanitize bool) (*[32]byte, error) {
	if sanitize {
		phrase = sanitizePhrase(phrase)
	}
	b, err := bip39.MnemonicToByteArray(phrase, true)
	if err != nil {
		return nil, ErrInvalidPhrase{cause: err}
	}
	if l := len(b); l != 32 {
		return nil, ErrInvalidPhrase{cause: errors.Errorf("invalid bip39 bytes length")}
	}
	var b32 [32]byte
	copy(b32[:], b[:32])
	return &b32, nil
}

func sanitizePhrase(phrase string) string {
	phrase = strings.TrimSpace(strings.ToLower(phrase))
	return strings.Join(strings.Fields(phrase), " ")
}

// IsValidPhrase checks is phrase is valid
func IsValidPhrase(phrase string, sanitize bool) bool {
	if sanitize {
		phrase = sanitizePhrase(phrase)
	}
	return bip39.IsMnemonicValid(phrase)
}
