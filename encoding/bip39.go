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

func (e ErrInvalidPhrase) Error() string {
	return "invalid phrase"
}

// Cause for ErrInvalidPhrase
func (e ErrInvalidPhrase) Cause() error {
	return e.cause
}

// BytesToPhrase returns a phrase for bytes
func BytesToPhrase(b []byte) (string, error) {
	return bip39.NewMnemonic(b)
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
