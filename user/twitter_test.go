package user_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/user"
	"github.com/stretchr/testify/require"
)

func TestNewUserForTwitterSigning(t *testing.T) {
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

	err = user.Verify(msg, usr)
	require.NoError(t, err)
}
