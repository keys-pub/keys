package keys

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindStringInHTML(t *testing.T) {
	msg, err := findStringInHTML("")
	require.NoError(t, err)
	require.Equal(t, "", msg)

	msg2, err := findStringInHTML("??")
	require.NoError(t, err)
	require.Equal(t, "", msg2)

	msg3, err := findStringInHTML("abc BEGIN MESSAGE.END MESSAGE. def")
	require.NoError(t, err)
	require.Equal(t, "BEGIN MESSAGE.END MESSAGE.", msg3)

	msg4, err := findStringInHTML("abc BEGIN MESSAGE. ok END MESSAGE. def")
	require.NoError(t, err)
	require.Equal(t, "BEGIN MESSAGE. ok END MESSAGE.", msg4)
}

func TestBreakString(t *testing.T) {
	s := ""
	for i := 1000; i < 1020; i++ {
		s = s + fmt.Sprintf("%d", i)
	}
	msg := breakString(s, 12, 5)
	expected := `100010011002 100310041005 100610071008 100910101011 101210131014
101510161017 10181019`
	require.Equal(t, expected, msg)
}

func TestTrimMessage(t *testing.T) {
	msg := trimMessage(">> abcdefghijklmnopqrstuvwxyz @@@ ABCXDEFGHIJKLMNOPQRSTUVWXYZ\n > 0123456789.    ")
	expected := "abcdefghijklmnopqrstuvwxyzABCXDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	require.Equal(t, expected, msg)
}
