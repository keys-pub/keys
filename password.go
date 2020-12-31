package keys

import (
	"crypto/rand"
	"math/big"
	mathRand "math/rand" // Only for shuffle
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

const lower = "abcdefghijklmnopqrstuvwxyz"
const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numbers = "0123456789"
const symbols = "~!@#$%^&*()_+`-={}|[]\\:\"<>?,./"

// PasswordOptions for RandPassword.
type PasswordOptions struct {
	NoSymbols bool
}

// RandPassword returns a random password.
// It will contain an uppercase (A-Z), lowercase (a-z), number (0-9) and symbol.
// It will not to repeat characters.
func RandPassword(length int, opt ...PasswordOption) string {
	opts := newPasswordOptions(opt...)
	charSet := lower + upper + numbers
	if !opts.NoSymbols {
		charSet += symbols
	}

	b := make([]byte, 0, length)
	i := 0
	for i < length-4 {
		b = append(b, randomChar(charSet, b))
		i++
	}

	// To ensure we have at least an uppercase, lowercase, number, symbol
	// append one of each and then shuffle.
	b = append(b, randomChar(upper, b))
	b = append(b, randomChar(lower, b))
	b = append(b, randomChar(numbers, b))

	if !opts.NoSymbols {
		b = append(b, randomChar(symbols, b))
	} else {
		b = append(b, randomChar(charSet, b))
	}

	// Shuffle doesn't need to be secure random
	mathRand.Seed(time.Now().UnixNano())
	mathRand.Shuffle(len(b), func(i, j int) {
		b[i], b[j] = b[j], b[i]
	})

	// Ensure max length
	b = b[:length]

	return string(b)
}

// PasswordOption ...
type PasswordOption func(*PasswordOptions)

func newPasswordOptions(opts ...PasswordOption) PasswordOptions {
	var options PasswordOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// NoSymbols password option.
func NoSymbols() PasswordOption {
	return func(o *PasswordOptions) {
		o.NoSymbols = true
	}
}

func randInt64(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	return n.Int64()
}

func randomChar(charSet string, b []byte) byte {
	var except byte
	if len(b) > 0 {
		except = b[len(b)-1]
	}
	for {
		r := randomCharFromSet(charSet)
		if r != except {
			return r
		}
	}
}

func randomCharFromSet(charSet string) byte {
	n := randInt64(int64(len(charSet)))
	return charSet[n]
}

// KeyForPassword generates a key from a password and salt.
func KeyForPassword(password string, salt []byte) (*[32]byte, error) {
	if len(salt) < 16 {
		return nil, errors.Errorf("not enough salt")
	}
	if password == "" {
		return nil, errors.Errorf("empty password")
	}

	akey := argon2.IDKey([]byte(password), salt[:], 1, 64*1024, 4, 32)
	return Bytes32(akey), nil
}
