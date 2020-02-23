package encoding_test

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/stretchr/testify/require"
)

func TestBreakString(t *testing.T) {
	s := ""
	for i := 1000; i < 1020; i++ {
		s = s + fmt.Sprintf("%d", i)
	}
	msg := encoding.BreakString(s, 12, 5)
	expected := `100010011002 100310041005 100610071008 100910101011 101210131014
101510161017 10181019`
	require.Equal(t, expected, msg)
}

func TestTrimSaltpack(t *testing.T) {
	msg := encoding.TrimSaltpack(">> abcdefghijklmnopqrstuvwxyz @@@ ABCXDEFGHIJKLMNOPQRSTUVWXYZ\n > 0123456789.    ", false)
	expected := "abcdefghijklmnopqrstuvwxyzABCXDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	require.Equal(t, expected, msg)
}

func TestFindInTwitter(t *testing.T) {
	b, err := ioutil.ReadFile("../testdata/twitter/1205589994380783616")
	require.NoError(t, err)

	s, brand := encoding.FindSaltpack(string(b), true)
	expected := `FD0Lv2C2AtvqD1XEwqDo1tOTkv8LKisQMlS6gluxz0npc1S2MuNVOfTph934h1xXQqj5EtueEBntfhbDceoOBETCKq6Xr2MZHgg4UNRDbZy2loGoGN3Mvxd4r7FIwpZOJPE1JEqD2gGjkgLByR9CFG2aCgRgZZwl5UAa46bmBzjE5yyl9oNKSO6lAVCOrl3JBganxnssAnkQt3vM3TdJOf`
	require.Equal(t, expected, s)
	require.Equal(t, "", brand)
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
