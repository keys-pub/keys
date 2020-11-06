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

	encrypted, err := Encrypt(message, xalice, xbob.ID())
	require.NoError(t, err)
	detected := detectEncrypt(encrypted)
	require.Equal(t, EncryptEncoding, detected.Encoding)
	require.False(t, detected.Armored)

	out, err := EncryptArmored(message, "TEST", xalice, xbob.ID())
	require.NoError(t, err)
	detected = detectEncrypt([]byte(out))
	require.Equal(t, EncryptEncoding, detected.Encoding)
	// TODO: Fix brand detect
	// require.Equal(t, "TEST", detected.Brand)
	require.True(t, detected.Armored)

	signcrypted, err := Signcrypt(message, alice, bob.ID())
	require.NoError(t, err)
	detected = detectEncrypt([]byte(signcrypted))
	require.Equal(t, SigncryptEncoding, detected.Encoding)
	require.False(t, detected.Armored)

	out, err = SigncryptArmored(message, "TEST", alice, bob.ID())
	require.NoError(t, err)
	detected = detectEncrypt([]byte(out))
	require.Equal(t, SigncryptEncoding, detected.Encoding)
	// TODO: Fix brand detect
	// require.Equal(t, "TEST", detected.Brand)
	require.True(t, detected.Armored)

	detected = detectEncrypt([]byte{0x01})
	require.Equal(t, UnknownEncoding, detected.Encoding)
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
