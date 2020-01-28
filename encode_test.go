package keys

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEncoding(t *testing.T) {
	enc, err := ParseEncoding("base1000")
	require.EqualError(t, err, "invalid encoding base1000")
	require.Equal(t, NoEncoding, enc)

	enc2, err := ParseEncoding("base64")
	require.NoError(t, err)
	require.Equal(t, Base64, enc2)
}

func TestEncode(t *testing.T) {
	s := MustEncode([]byte("🤓"), Base62)
	require.Equal(t, "4PCobb", s)

	s = MustEncode([]byte("🤓"), Base64)
	require.Equal(t, "8J+kkw==", s)

	s = MustEncode([]byte("🤓🤓🤓🤓🤓"), Saltpack)
	require.Equal(t, "YKecp8NtwMvKIdy lDKcKhWX0nGV.", s)

	s = MustEncode(bytes.Repeat([]byte{0x01}, 32), BIP39)
	require.Equal(t, "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic", s)

	s = MustEncode(bytes.Repeat([]byte{0x01}, 32), Hex)
	require.Equal(t, "0101010101010101010101010101010101010101010101010101010101010101", s)

	s = MustEncode(bytes.Repeat([]byte{0x01}, 32), Base58)
	require.Equal(t, "1BfGRZL7c75qu5bFwXXjWpmRmz15rJ1q6oLzUX9GJk2c", s)

	s = MustEncode([]byte("test"), Base58)
	require.Equal(t, "3yZe7d", s)
}

func TestIsASCII(t *testing.T) {
	ok := IsASCII([]byte("ok"))
	require.True(t, ok)

	ok2 := IsASCII([]byte{0xFF})
	require.False(t, ok2)
}

func TestDecode(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03, 0x04}
	s := "AQIDBA=="
	bout, err := Decode(s, Base64)
	require.NoError(t, err)
	require.Equal(t, b, bout)

	bout, err = Decode("YKecp8NtwMvKIdy lDKcKhWX0nGV.", Saltpack)
	require.NoError(t, err)
	require.Equal(t, []byte("🤓🤓🤓🤓🤓"), bout)
}

func TestHasUpper(t *testing.T) {
	ok := hasUpper("ok")
	require.False(t, ok)

	ok2 := hasUpper("Ok")
	require.True(t, ok2)
}

func TestSaltpackEncode(t *testing.T) {
	b := bytes.Repeat([]byte{0x01}, 128)
	msg := EncodeSaltpack(b, "TEST")
	expected := `BEGIN TEST MESSAGE.
0El6XFXwsUFD8J2 vGxsaboW7rZYnQR BP5d9erwRwd290E l6XFXwsUFD8J2vG
xsaboW7rZYnQRBP 5d9erwRwd290El6 XFXwsUFD8J2vGxs aboW7rZYnQRBP5d
9erwRwd290El6XF XwsUFD8J2vGxsab oW7rZYnQRBP5d9e rwRwd29.
END TEST MESSAGE.`
	require.Equal(t, expected, msg)

	out, brand, err := DecodeSaltpack(msg, false)
	require.NoError(t, err)
	require.Equal(t, b, out)
	require.Equal(t, "TEST", brand)

	msg = EncodeSaltpack(b, "")
	expected = `BEGIN MESSAGE.
0El6XFXwsUFD8J2 vGxsaboW7rZYnQR BP5d9erwRwd290E l6XFXwsUFD8J2vG
xsaboW7rZYnQRBP 5d9erwRwd290El6 XFXwsUFD8J2vGxs aboW7rZYnQRBP5d
9erwRwd290El6XF XwsUFD8J2vGxsab oW7rZYnQRBP5d9e rwRwd29.
END MESSAGE.`
	require.Equal(t, expected, msg)
}

func TestEncodeDecodeKey(t *testing.T) {
	sk := GenerateEdX25519Key()
	msg, err := EncodeKeyToSaltpack(sk, "testpassword")
	require.NoError(t, err)

	t.Logf(msg)

	_, err = DecodeKeyFromSaltpack(msg, "invalidpassword", false)
	require.EqualError(t, err, "failed to decrypt saltpack encoded key: failed to decrypt with a password: secretbox open failed")

	skOut, err := DecodeKeyFromSaltpack(msg, "testpassword", false)
	require.NoError(t, err)

	require.Equal(t, sk.Type(), skOut.Type())
	require.Equal(t, sk.Bytes(), skOut.Bytes())
}
