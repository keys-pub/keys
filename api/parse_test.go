package api_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	kid := "kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"
	key, err := api.ParseKey([]byte(kid), "")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), key.ID)

	// SSH public ed25519
	edPub := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ4jWl0FmuOcpONIojVzigw30/NppVZjiPvJGbmLKP2P gabe@ok.local`
	key, err = api.ParseKey([]byte(edPub), "")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), key.ID)

	// SSH private ed25519
	edPriv := `-----BEGIN OPENSSH PRIVATE KEY-----
	b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
	QyNTUxOQAAACCeI1pdBZrjnKTjSKI1c4oMN9PzaaVWY4j7yRm5iyj9jwAAAJDRmZP80ZmT
	/AAAAAtzc2gtZWQyNTUxOQAAACCeI1pdBZrjnKTjSKI1c4oMN9PzaaVWY4j7yRm5iyj9jw
	AAAED2F09VUc5ig2cF/HpYJQM6Jzin26cDxFGELnR5HRIF3Z4jWl0FmuOcpONIojVzigw3
	0/NppVZjiPvJGbmLKP2PAAAADWdhYmVAb2subG9jYWw=
	-----END OPENSSH PRIVATE KEY-----`
	key, err = api.ParseKey([]byte(edPriv), "")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1nc345hg9nt3eef8rfz3r2uu2psma8umf54tx8z8meyvmnzeglk8s50xu7y"), key.ID)

	// Saltpack
	sp := `BEGIN EDX25519 KEY MESSAGE.
	GSXg1PCawOlgXTp IoXa8FHPFV82MkC xrXzl7k2Scj2CK0 R9ezilK7VqWsLWv
	TF3WxURVAhzQmNY uJoEJXKYiWJIY4K gMQTVtndovcxjho KBu5yu4Wm7nM6Bh
	mjqGVIo5r0NXW4N ZsKF3NJ01o98tpJ 9KrsbBFsBd2V.
	END EDX25519 KEY MESSAGE.`
	key, err = api.ParseKey([]byte(sp), "testpassword")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex1lm9tc5cmgr0u4tg7q2tl9fxzdcke89c5sl8jnjpkr6erv88m4nvq5cg7n8"), key.ID)

	// API
	ak := `BEGIN KEY MESSAGE.
	Z7SesuE0476OHgx zzBpDJEvtBIyvoh Eu6n8n2GraBGi4C Mn5PBpSxOUXYmtv
	egz6h4JDxL2UkJL v47Yc4poDkkUcro 9tysFbWqf6oeXiJ CTrSWP9s6gaLZMg
	hBvwd1RW1ifzjDz 1l9Bzi1g3CqWmn1 DUgIxOA6EADOxYP 4RfPgpGpUxGNrBH
	JdH0L5km70jlpx3 BD1mfWV3r39HWbd x8lM1c3kIV8P0DF sjt7e5w8x30dNG3
	FXem1iDVpR0C6tk VHAgHbb7Ik44CbZ 3h4KfcJMsv2wvzq kiN9BGWl8swIuGY
	KWcZYo1P7lZPaKo K3rnMUvTkis4XWL 1URW1r2810ASXvh XYLetugWobu0PPl
	FIinNIJ9w044N8x MYixY8rboFIHdxn fsEueZrN4zXUzBE VxTdljPsRGVOsj1
	G6mQQPYrQy1O.
	END KEY MESSAGE.`
	key, err = api.ParseKey([]byte(ak), "")
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex135n03rgjrenhac4r92y4stfcy84rcc3tcgpwm6yl55uc0hg7h4eq3ntlut"), key.ID)
}
