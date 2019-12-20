package keys

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretBox(t *testing.T) {
	sk := GenerateSecretKey()
	nonce := Bytes24(bytes.Repeat([]byte{0x0F}, 24))
	b := []byte{0x01, 0x02, 0x03}
	encrypted := sealSecretBox(b, nonce, sk)
	out, err := openSecretBox(encrypted, sk)
	require.NoError(t, err)
	assert.Equal(t, b, out)
}

func TestSealWithPassword(t *testing.T) {
	b := bytes.Repeat([]byte{0x01}, 64)
	encrypted := SealWithPassword(b, "password123")

	out, err := OpenWithPassword(encrypted, "password123")
	require.NoError(t, err)
	require.Equal(t, b, out)

	out, err = OpenWithPassword(encrypted, "invalid")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")

	out, err = OpenWithPassword([]byte{}, "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = OpenWithPassword(bytes.Repeat([]byte{0x01}, 16), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = OpenWithPassword(bytes.Repeat([]byte{0x01}, 24), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = OpenWithPassword(bytes.Repeat([]byte{0x01}, 32), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = OpenWithPassword(bytes.Repeat([]byte{0x01}, 40), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")
}
