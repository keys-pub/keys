package request_test

import (
	"context"
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/request"
	"github.com/stretchr/testify/require"
)

// TODO: more tests are in users package

func TestTwitterNewUserForSigning(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	usr, err := user.NewForSigning(sk.ID(), "twitter", "123456789012345")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	expected := `BEGIN MESSAGE.
GaZybOsIjCQ9nU5 QoXI1pS28UWypBb HHSXegeFk1M6huT W5rwWMtO4Gcx4u3
Gjbya7YnsVfnAVz xvTtqmINcMmTCKq 6Xr2MZHgg4UNRDb Zy2loGoGN3Mvxd4
r7FIwpZOJPE1JEq D2gGjkgLByR9CFG 2aCgRgZZwl5UAa4 6bmBzjEOhmsiW0K
TDXulMojfPebRMl JBdGc81U8wUvF0I 1LUOo5fLogY3MDW UqhLx.
END MESSAGE.`
	require.Equal(t, expected, msg)
	require.False(t, len(msg) > 280)
	require.Equal(t, 274, len(msg))

	err = usr.Verify(msg)
	require.NoError(t, err)
}

func TestTwitter(t *testing.T) {
	// Requires twitter bearer token configured
	if os.Getenv("TWITTER_BEARER_TOKEN") == "" {
		t.Skip("no auth")
	}
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// services.SetLogger(user.NewLogger(user.DebugLevel))

	kid := keys.ID("kex1e26rq9vrhjzyxhep0c5ly6rudq7m2cexjlkgknl2z4lqf8ga3uasz3s48m")
	urs := "https://twitter.com/gabrlh/status/1222706272849391616"

	usr, err := user.New(kid, "twitter", "gabrlh", urs, 1)
	require.NoError(t, err)
	client := http.NewClient()
	st, _, err := request.Verify(context.TODO(), client, usr)
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, st)
	// TODO: Require msg
}
