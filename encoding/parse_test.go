package encoding_test

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/keys-pub/keys/encoding"
	"github.com/stretchr/testify/require"
)

func testdata(t *testing.T, path string) string {
	expected, err := ioutil.ReadFile(path)
	require.NoError(t, err)
	return strings.ReplaceAll(string(expected), "\r\n", "\n")
}

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
	data := testdata(t, "../testdata/twitter/1205589994380783616")
	s, brand := encoding.FindSaltpack(data, true)
	expected := `FD0Lv2C2AtvqD1XEwqDo1tOTkv8LKisQMlS6gluxz0npc1S2MuNVOfTph934h1xXQqj5EtueEBntfhbDceoOBETCKq6Xr2MZHgg4UNRDbZy2loGoGN3Mvxd4r7FIwpZOJPE1JEqD2gGjkgLByR9CFG2aCgRgZZwl5UAa46bmBzjE5yyl9oNKSO6lAVCOrl3JBganxnssAnkQt3vM3TdJOf`
	require.Equal(t, expected, s)
	require.Equal(t, "", brand)
}
