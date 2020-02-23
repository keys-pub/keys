package encoding_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/stretchr/testify/require"
)

func TestParseEncoding(t *testing.T) {
	enc, err := encoding.Parse("base1000")
	require.EqualError(t, err, "invalid encoding base1000")
	require.Equal(t, encoding.NoEncoding, enc)

	enc2, err := encoding.Parse("base64")
	require.NoError(t, err)
	require.Equal(t, encoding.Base64, enc2)
}

func TestEncode(t *testing.T) {
	s := encoding.MustEncode([]byte("🤓"), encoding.Base62)
	require.Equal(t, "4PCobb", s)

	s = encoding.MustEncode([]byte("🤓"), encoding.Base64)
	require.Equal(t, "8J+kkw==", s)

	s = encoding.MustEncode([]byte("🤓🤓🤓🤓🤓"), encoding.Saltpack)
	require.Equal(t, "YKecp8NtwMvKIdy lDKcKhWX0nGV.", s)

	s = encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.BIP39)
	require.Equal(t, "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic", s)

	s = encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Hex)
	require.Equal(t, "0101010101010101010101010101010101010101010101010101010101010101", s)

	s = encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base58)
	require.Equal(t, "1BfGRZL7c75qu5bFwXXjWpmRmz15rJ1q6oLzUX9GJk2c", s)

	s = encoding.MustEncode([]byte("test"), encoding.Base58)
	require.Equal(t, "3yZe7d", s)
}

func TestIsASCII(t *testing.T) {
	ok := encoding.IsASCII([]byte("ok"))
	require.True(t, ok)

	ok2 := encoding.IsASCII([]byte{0xFF})
	require.False(t, ok2)
}

func TestDecode(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04}
	s := "AQIDBA=="
	bout, err := encoding.Decode(s, encoding.Base64)
	require.NoError(t, err)
	require.Equal(t, b, bout)

	bout, err = encoding.Decode("YKecp8NtwMvKIdy lDKcKhWX0nGV.", encoding.Saltpack)
	require.NoError(t, err)
	require.Equal(t, []byte("🤓🤓🤓🤓🤓"), bout)
}

func TestHasUpper(t *testing.T) {
	ok := encoding.HasUpper("ok")
	require.False(t, ok)

	ok2 := encoding.HasUpper("Ok")
	require.True(t, ok2)
}
