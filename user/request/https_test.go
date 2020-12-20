package request_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/request"
	"github.com/stretchr/testify/require"
)

func TestHTTPS(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex1ydecaulsg5qty2axyy770cjdvqn3ef2qa85xw87p09ydlvs5lurq53x0p3")

	usr, err := user.New(kid, "https", "keys.pub", "https://keys.pub/keyspub.txt", 1)
	require.NoError(t, err)
	client := http.NewClient()
	st, msg, err := request.Verify(context.TODO(), client, usr)
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, st)
	expected := `BEGIN MESSAGE.
7PPiOMcdjhvnXzM 1uVwr224ccgiOKt I5vwzYoRY3xgUdL 86O3X1DnuZwCTIP
ACnuZKXBB4y39qQ f7sq7eoQs8oTCKq 6Xr2MZHgg7F8Mca NbI7en6mNzlIVvQ
zIh84hprPPEByeP D9s1xc5HURCNFcv rsOvrUoV0oHQfyi 89aehuNSV2AP9hp
8dGT8SwS3TEo3FP b1X8S32XyBenWKF aJv7L2IP.
END MESSAGE.`
	require.Equal(t, expected, msg)
}
