package saltpack

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestDetectEncrypt(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	message := []byte("hi bob")
	xalice := alice.X25519Key()
	xbob := bob.X25519Key()

	encrypted, err := Encrypt(message, false, xalice, xbob.ID())
	require.NoError(t, err)
	enc, armored := detectEncrypt(encrypted)
	require.Equal(t, EncryptEncoding, enc)
	require.False(t, armored)

	out, err := Encrypt(message, true, xalice, xbob.ID())
	require.NoError(t, err)
	enc, armored = detectEncrypt([]byte(out))
	require.Equal(t, EncryptEncoding, enc)
	require.True(t, armored)

	signcrypted, err := Signcrypt(message, false, alice, bob.ID())
	require.NoError(t, err)
	enc, armored = detectEncrypt([]byte(signcrypted))
	require.Equal(t, SigncryptEncoding, enc)
	require.True(t, armored)

	out, err = Signcrypt(message, true, alice, bob.ID())
	require.NoError(t, err)
	enc, armored = detectEncrypt([]byte(out))
	require.Equal(t, SigncryptEncoding, enc)
	require.True(t, armored)

	enc, _ = detectEncrypt([]byte{0x01})
	require.Equal(t, UnknownEncoding, enc)
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
