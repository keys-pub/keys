package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestEncodeKeyToSaltpack(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	msg, err := keys.EncodeSaltpackKey(sk, "testpassword")
	require.NoError(t, err)

	_, err = keys.DecodeSaltpackKey(msg, "invalidpassword", false)
	require.EqualError(t, err, "failed to decrypt saltpack encoded key: failed to decrypt with a password: secretbox open failed")

	skOut, err := keys.DecodeSaltpackKey(msg, "testpassword", false)
	require.NoError(t, err)

	require.Equal(t, sk.Type(), skOut.Type())
	require.Equal(t, sk.Bytes(), skOut.Bytes())
}

func TestEncodeKeyDecodeKey(t *testing.T) {
	sk := keys.GenerateEdX25519Key()

	// Saltpack (password)
	msg, err := keys.EncodeKey(sk, keys.SaltpackEncoding, "testpassword")
	require.NoError(t, err)
	out, err := keys.DecodeKey(msg, keys.SaltpackEncoding, "testpassword")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())

	// Saltpack (no password)
	msg, err = keys.EncodeKey(sk, keys.SaltpackEncoding, "")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SaltpackEncoding, "")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())

	// Saltpack (public)
	msg, err = keys.EncodeKey(sk.PublicKey(), keys.SaltpackEncoding, "")
	require.EqualError(t, err, "failed to encode to saltpack: unsupported key ed25519-public")

	// SSH (public)
	msg, err = keys.EncodeKey(sk.PublicKey(), keys.SSHEncoding, "")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SSHEncoding, "")
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Type(), out.Type())
	require.Equal(t, sk.PublicKey().Bytes(), out.Bytes())

	// SSH (password)
	msg, err = keys.EncodeKey(sk, keys.SSHEncoding, "testpassword")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SSHEncoding, "testpassword")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())

	// SSH (no password)
	msg, err = keys.EncodeKey(sk, keys.SSHEncoding, "")
	require.NoError(t, err)
	out, err = keys.DecodeKey(msg, keys.SSHEncoding, "")
	require.NoError(t, err)
	require.Equal(t, sk.Type(), out.Type())
	require.Equal(t, sk.Bytes(), out.Bytes())
}
