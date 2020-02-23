package encoding_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/stretchr/testify/require"
)

func TestSaltpackEncode(t *testing.T) {
	b := bytes.Repeat([]byte{0x01}, 128)
	msg := encoding.EncodeSaltpack(b, "TEST")
	expected := `BEGIN TEST MESSAGE.
0El6XFXwsUFD8J2 vGxsaboW7rZYnQR BP5d9erwRwd290E l6XFXwsUFD8J2vG
xsaboW7rZYnQRBP 5d9erwRwd290El6 XFXwsUFD8J2vGxs aboW7rZYnQRBP5d
9erwRwd290El6XF XwsUFD8J2vGxsab oW7rZYnQRBP5d9e rwRwd29.
END TEST MESSAGE.`
	require.Equal(t, expected, msg)

	out, brand, err := encoding.DecodeSaltpack(msg, false)
	require.NoError(t, err)
	require.Equal(t, b, out)
	require.Equal(t, "TEST", brand)

	msg = encoding.EncodeSaltpack(b, "")
	expected = `BEGIN MESSAGE.
0El6XFXwsUFD8J2 vGxsaboW7rZYnQR BP5d9erwRwd290E l6XFXwsUFD8J2vG
xsaboW7rZYnQRBP 5d9erwRwd290El6 XFXwsUFD8J2vGxs aboW7rZYnQRBP5d
9erwRwd290El6XF XwsUFD8J2vGxsab oW7rZYnQRBP5d9e rwRwd29.
END MESSAGE.`
	require.Equal(t, expected, msg)
}
