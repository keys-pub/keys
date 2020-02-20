package keys_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestParseEncoding(t *testing.T) {
	enc, err := keys.ParseEncoding("base1000")
	require.EqualError(t, err, "invalid encoding base1000")
	require.Equal(t, keys.NoEncoding, enc)

	enc2, err := keys.ParseEncoding("base64")
	require.NoError(t, err)
	require.Equal(t, keys.Base64, enc2)
}

func TestEncode(t *testing.T) {
	s := keys.MustEncode([]byte("🤓"), keys.Base62)
	require.Equal(t, "4PCobb", s)

	s = keys.MustEncode([]byte("🤓"), keys.Base64)
	require.Equal(t, "8J+kkw==", s)

	s = keys.MustEncode([]byte("🤓🤓🤓🤓🤓"), keys.Saltpack)
	require.Equal(t, "YKecp8NtwMvKIdy lDKcKhWX0nGV.", s)

	s = keys.MustEncode(bytes.Repeat([]byte{0x01}, 32), keys.BIP39)
	require.Equal(t, "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic", s)

	s = keys.MustEncode(bytes.Repeat([]byte{0x01}, 32), keys.Hex)
	require.Equal(t, "0101010101010101010101010101010101010101010101010101010101010101", s)

	s = keys.MustEncode(bytes.Repeat([]byte{0x01}, 32), keys.Base58)
	require.Equal(t, "1BfGRZL7c75qu5bFwXXjWpmRmz15rJ1q6oLzUX9GJk2c", s)

	s = keys.MustEncode([]byte("test"), keys.Base58)
	require.Equal(t, "3yZe7d", s)
}

func TestIsASCII(t *testing.T) {
	ok := keys.IsASCII([]byte("ok"))
	require.True(t, ok)

	ok2 := keys.IsASCII([]byte{0xFF})
	require.False(t, ok2)
}

func TestDecode(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04}
	s := "AQIDBA=="
	bout, err := keys.Decode(s, keys.Base64)
	require.NoError(t, err)
	require.Equal(t, b, bout)

	bout, err = keys.Decode("YKecp8NtwMvKIdy lDKcKhWX0nGV.", keys.Saltpack)
	require.NoError(t, err)
	require.Equal(t, []byte("🤓🤓🤓🤓🤓"), bout)
}

func TestHasUpper(t *testing.T) {
	ok := keys.HasUpper("ok")
	require.False(t, ok)

	ok2 := keys.HasUpper("Ok")
	require.True(t, ok2)
}

func TestSaltpackEncode(t *testing.T) {
	b := bytes.Repeat([]byte{0x01}, 128)
	msg := keys.EncodeSaltpack(b, "TEST")
	expected := `BEGIN TEST MESSAGE.
0El6XFXwsUFD8J2 vGxsaboW7rZYnQR BP5d9erwRwd290E l6XFXwsUFD8J2vG
xsaboW7rZYnQRBP 5d9erwRwd290El6 XFXwsUFD8J2vGxs aboW7rZYnQRBP5d
9erwRwd290El6XF XwsUFD8J2vGxsab oW7rZYnQRBP5d9e rwRwd29.
END TEST MESSAGE.`
	require.Equal(t, expected, msg)

	out, brand, err := keys.DecodeSaltpack(msg, false)
	require.NoError(t, err)
	require.Equal(t, b, out)
	require.Equal(t, "TEST", brand)

	msg = keys.EncodeSaltpack(b, "")
	expected = `BEGIN MESSAGE.
0El6XFXwsUFD8J2 vGxsaboW7rZYnQR BP5d9erwRwd290E l6XFXwsUFD8J2vG
xsaboW7rZYnQRBP 5d9erwRwd290El6 XFXwsUFD8J2vGxs aboW7rZYnQRBP5d
9erwRwd290El6XF XwsUFD8J2vGxsab oW7rZYnQRBP5d9e rwRwd29.
END MESSAGE.`
	require.Equal(t, expected, msg)
}

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
