package saltpack_test

import (
	"bytes"

	"github.com/keys-pub/keys"
)

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
