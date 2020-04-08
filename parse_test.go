package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestParseKey(t *testing.T) {
	kid := "kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"
	key, err := keys.ParseKey([]byte(kid), "")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), key.ID())

	ed := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ4jWl0FmuOcpONIojVzigw30/NppVZjiPvJGbmLKP2P gabe@ok.local`
	key, err = keys.ParseKey([]byte(ed), "")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), key.ID())

	edpriv := `-----BEGIN OPENSSH PRIVATE KEY-----
	b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
	QyNTUxOQAAACCeI1pdBZrjnKTjSKI1c4oMN9PzaaVWY4j7yRm5iyj9jwAAAJDRmZP80ZmT
	/AAAAAtzc2gtZWQyNTUxOQAAACCeI1pdBZrjnKTjSKI1c4oMN9PzaaVWY4j7yRm5iyj9jw
	AAAED2F09VUc5ig2cF/HpYJQM6Jzin26cDxFGELnR5HRIF3Z4jWl0FmuOcpONIojVzigw3
	0/NppVZjiPvJGbmLKP2PAAAADWdhYmVAb2subG9jYWw=
	-----END OPENSSH PRIVATE KEY-----`
	key, err = keys.ParseKey([]byte(edpriv), "")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), key.ID())

	sp := `BEGIN EDX25519 KEY MESSAGE.
	GSXg1PCawOlgXTp IoXa8FHPFV82MkC xrXzl7k2Scj2CK0 R9ezilK7VqWsLWv
	TF3WxURVAhzQmNY uJoEJXKYiWJIY4K gMQTVtndovcxjho KBu5yu4Wm7nM6Bh
	mjqGVIo5r0NXW4N ZsKF3NJ01o98tpJ 9KrsbBFsBd2V.
	END EDX25519 KEY MESSAGE.`
	key, err = keys.ParseKey([]byte(sp), "testpassword")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1lm9tc5cmgr0u4tg7q2tl9fxzdcke89c5sl8jnjpkr6erv88m4nvq5cg7n8"), key.ID())
}
