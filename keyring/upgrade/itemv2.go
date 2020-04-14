package upgrade

import (
	"crypto/rand"
	"time"

	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
	"golang.org/x/crypto/nacl/secretbox"
)

type itemV2 struct {
	ID        string
	Type      string
	Data      []byte
	CreatedAt time.Time
}

func marshalV2(item *itemV2, secretKey *[32]byte) ([]byte, error) {
	if secretKey == nil {
		return nil, errors.Errorf("no secret key specified")
	}
	b, err := msgpack.Marshal(item)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal kerying item")
	}
	encrypted := secretBoxSeal(b, secretKey)
	return encrypted, nil
}

func randBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return buf
}

func rand24() *[24]byte {
	b := randBytes(24)
	var b24 [24]byte
	copy(b24[:], b[:24])
	return &b24
}

func secretBoxSeal(b []byte, secretKey *[32]byte) []byte {
	nonce := rand24()
	encrypted := secretbox.Seal(nil, b, nonce, secretKey)
	encrypted = append(nonce[:], encrypted...)
	return encrypted
}

func secretBoxOpen(encrypted []byte, secretKey *[32]byte) ([]byte, bool) {
	if secretKey == nil {
		return nil, false
	}
	if len(encrypted) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	encrypted = encrypted[24:]

	return secretbox.Open(nil, encrypted, &nonce, secretKey)
}
