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

func TestEncodeBase32(t *testing.T) {
	var out string
	b := bytes.Repeat([]byte{0x01}, 32)

	out = encoding.MustEncode(b, encoding.Base32)
	require.Equal(t, "AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQ====", out)
	out = encoding.MustEncode(b, encoding.Base32, encoding.NoPadding())
	require.Equal(t, "AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQ", out)
	out = encoding.MustEncode(b, encoding.Base32, encoding.NoPadding(), encoding.Lowercase())
	require.Equal(t, "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq", out)
}

func TestEncodeBase64(t *testing.T) {
	var out string
	var err error
	b := bytes.Repeat([]byte{0x01}, 32)

	out = encoding.MustEncode(b, encoding.Base64)
	require.Equal(t, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", out)
	out = encoding.MustEncode(b, encoding.Base64, encoding.NoPadding())
	require.Equal(t, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", out)
	out, err = encoding.Encode(b, encoding.Base64, encoding.NoPadding(), encoding.Lowercase())
	require.EqualError(t, err, "invalid option: lowercase")
}
