package keys_test

import (
	"encoding/hex"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestHKDFSHA256Vectors(t *testing.T) {
	// https://tools.ietf.org/html/rfc5869, appendix A
	secret, err := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	require.NoError(t, err)
	salt, err := hex.DecodeString("000102030405060708090a0b0c")
	require.NoError(t, err)
	info, err := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	require.NoError(t, err)
	len := 42

	out := keys.HKDFSHA256(secret, len, salt, info)
	expected, err := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	require.NoError(t, err)
	require.Equal(t, expected, out)
}
