package keys_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestSecretBox(t *testing.T) {
	sk := keys.Rand32()
	b := []byte{0x01, 0x02, 0x03}
	encrypted := keys.SecretBoxSeal(b, sk)
	out, err := keys.SecretBoxOpen(encrypted, sk)
	require.NoError(t, err)
	require.Equal(t, b, out)
}

func TestEncryptWithPassword(t *testing.T) {
	b := bytes.Repeat([]byte{0x01}, 64)
	encrypted := keys.EncryptWithPassword(b, "password123")

	out, err := keys.DecryptWithPassword(encrypted, "password123")
	require.NoError(t, err)
	require.Equal(t, b, out)

	out, err = keys.DecryptWithPassword(encrypted, "invalid")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")

	out, err = keys.DecryptWithPassword([]byte{}, "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 16), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 24), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 32), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: not enough bytes")

	out, err = keys.DecryptWithPassword(bytes.Repeat([]byte{0x01}, 40), "password123")
	require.Nil(t, out)
	require.EqualError(t, err, "failed to decrypt with a password: secretbox open failed")
}
