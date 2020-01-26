package keys

import (
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindSaltpackStringInHTML(t *testing.T) {
	msg := findSaltpackMessageInHTML("", "")
	require.Equal(t, "", msg)

	msg = findSaltpackMessageInHTML("??", "")
	require.Equal(t, "", msg)

	msg = findSaltpackMessageInHTML("abc BEGIN MESSAGE.END MESSAGE. def", "")
	require.Equal(t, "BEGIN MESSAGE.END MESSAGE.", msg)

	msg = findSaltpackMessageInHTML("abc BEGIN MESSAGE. ok END MESSAGE. def", "")
	require.Equal(t, "BEGIN MESSAGE. ok END MESSAGE.", msg)

	msg = findSaltpackMessageInHTML("abc BEGIN TEST MESSAGE. ok END TEST MESSAGE. def", "TEST")
	require.Equal(t, "BEGIN TEST MESSAGE. ok END TEST MESSAGE.", msg)
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

func TestFindInTwitter(t *testing.T) {
	b, err := ioutil.ReadFile("testdata/twitter/1205589994380783616")
	require.NoError(t, err)

	msg := findSaltpackMessageInHTML(string(b), "")

	// t.Logf(msg)
	s, err := trimSaltpackInHTML(msg, "")
	require.NoError(t, err)
	expected := `4GzGHxrCV1mQX52SsmHqMRFVoFxjJ1U5MSWcBSZghX6c3pGpWnUnPM7yzXyUO174RObuLyx6Q8ndjy1KvBAMrTTCKq6Xr2MZu9OMNqdcBy5bhFeVoC3DU8LtGTf9lEuEJPE1JEqD2gGjkgLByR9CFG2aCgRgZZwl5UAa46bmBzzr5hHCbULzUPQDQhFimhSg2RdoCQj97oiDKhszZtgWSr`
	require.Equal(t, expected, s)
}
