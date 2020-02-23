package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeKey(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	msg, err := keys.EncodeKeyToSaltpack(sk, "testpassword")
	require.NoError(t, err)

	t.Logf(msg)

	_, err = keys.DecodeKeyFromSaltpack(msg, "invalidpassword", false)
	require.EqualError(t, err, "failed to decrypt saltpack encoded key: failed to decrypt with a password: secretbox open failed")

	skOut, err := keys.DecodeKeyFromSaltpack(msg, "testpassword", false)
	require.NoError(t, err)

	require.Equal(t, sk.Type(), skOut.Type())
	require.Equal(t, sk.Bytes(), skOut.Bytes())
}
