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

func TestFindSaltpack(t *testing.T) {
	msg, _ := encoding.FindSaltpack("", false)
	require.Equal(t, "", msg)

	msg, _ = encoding.FindSaltpack("??", false)
	require.Equal(t, "", msg)

	msg, _ = encoding.FindSaltpack("abc BEGIN MESSAGE.END MESSAGE. def", false)
	require.Equal(t, "", msg)

	msg, _ = encoding.FindSaltpack("abc BEGIN MESSAGE. ok END MESSAGE. def", false)
	require.Equal(t, "ok", msg)

	msg, brand := encoding.FindSaltpack("abc BEGIN TEST MESSAGE. ok END TEST MESSAGE. def", false)
	require.Equal(t, "ok", msg)
	require.Equal(t, "TEST", brand)

	msg = `BEGIN MESSAGE.
	l0eEt9tsSRb8xzE XvvgqPrizO9VJe9 AcsbRmIt5NoSP8A jLpClFdJJ1upFbI
	xxnKzSyXt6ltPcX WkaseWW5coa1e5V XvEMPpyt5IQii1Q 5ox8p3recj6hVN.
	END MESSAGE.`
	out, brand := encoding.FindSaltpack(msg, false)
	require.Equal(t, "l0eEt9tsSRb8xzEXvvgqPrizO9VJe9AcsbRmIt5NoSP8AjLpClFdJJ1upFbIxxnKzSyXt6ltPcXWkaseWW5coa1e5VXvEMPpyt5IQii1Q5ox8p3recj6hVN", out)
	require.Equal(t, "", brand)

	msg = `This is a saltpack encoded message... BEGIN EDX25519 KEY MESSAGE.
	l0eEt9tsSRb8xzE XvvgqPrizO9VJe9 AcsbRmIt5NoSP8A jLpClFdJJ1upFbI
	xxnKzSyXt6ltPcX WkaseWW5coa1e5V XvEMPpyt5IQii1Q 5ox8p3recj6hVN.
	END EDX25519 KEY MESSAGE. --`
	out, brand = encoding.FindSaltpack(msg, false)
	require.Equal(t, "l0eEt9tsSRb8xzEXvvgqPrizO9VJe9AcsbRmIt5NoSP8AjLpClFdJJ1upFbIxxnKzSyXt6ltPcXWkaseWW5coa1e5VXvEMPpyt5IQii1Q5ox8p3recj6hVN", out)
	require.Equal(t, "EDX25519 KEY", brand)

	msg = `This is a saltpack encoded message... BEGIN EDX25519 
	KEY MESSAGE.
	l0eEt9tsSRb8xzE XvvgqPrizO9VJe9 AcsbRmIt5NoSP8A jLpClFdJJ1upFbI
	xxnKzSyXt6ltPcX WkaseWW5coa1e5V XvEMPpyt5IQii1Q 5ox8p3recj6hVN.
	END EDX25519
	 KEY MESSAGE. --`
	out, brand = encoding.FindSaltpack(msg, false)
	require.Equal(t, "l0eEt9tsSRb8xzEXvvgqPrizO9VJe9AcsbRmIt5NoSP8AjLpClFdJJ1upFbIxxnKzSyXt6ltPcXWkaseWW5coa1e5VXvEMPpyt5IQii1Q5ox8p3recj6hVN", out)
	require.Equal(t, "EDX25519 KEY", brand)
}
