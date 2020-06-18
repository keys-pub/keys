package keys

import (
	"crypto/rand"
	"math/big"
	mathRand "math/rand" // Only for shuffle

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

const lower = "abcdefghijklmnopqrstuvwxyz"
const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numbers = "0123456789"
const alphaNumeric = lower + upper + numbers

// RandPassword returns a random password.
// It uses a-zA-Z0-9. It will contain an uppercase, a lowercase and a number.
// It will try not to repeat characters.
func RandPassword(length int) string {
	const maxRetry = 10

	b := make([]byte, 0, length)
	i := 0
	for i < length-3 {
		b = append(b, randUniqueChar(alphaNumeric, b, 0, maxRetry))
		i++
	}

	// Append uppercase, lowercase, number and then shuffle.
	b = append(b, randUniqueChar(upper, b, 0, maxRetry))
	b = append(b, randUniqueChar(lower, b, 0, maxRetry))
	b = append(b, randUniqueChar(numbers, b, 0, maxRetry))

	mathRand.Shuffle(len(b), func(i, j int) {
		b[i], b[j] = b[j], b[i]
	})

	return string(b[:length])
}

func randInt64(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	return n.Int64()
}

func randUniqueChar(charSet string, b []byte, retry int, maxRetry int) byte {
	r := randomChar(alphaNumeric)
	if hasByte(b, r) && retry < maxRetry {
		retry++
		return randUniqueChar(charSet, b, retry, maxRetry)
	}
	return r
}

func randomChar(charSet string) byte {
	n := randInt64(int64(len(charSet)))
	return charSet[n]
}

func hasByte(ba []byte, b byte) bool {
	for _, e := range ba {
		if e == b {
			return true
		}
	}
	return false
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
