package user_test

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/ds"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/util"
	"github.com/stretchr/testify/require"
)

type clock struct {
	t time.Time
}

func newClock() *clock {
	t := util.TimeFromMillis(1234567890000)
	return &clock{
		t: t,
	}
}

func (c *clock) Now() time.Time {
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func testdataString(t *testing.T, path string) string {
	expected, err := ioutil.ReadFile(filepath.Join("..", path))
	require.NoError(t, err)
	return strings.ReplaceAll(string(expected), "\r\n", "\n")
}

func testdataBytes(t *testing.T, path string) []byte {
	b, err := ioutil.ReadFile(filepath.Join("..", path))
	require.NoError(t, err)
	return b
}

func TestSigchainUsers(t *testing.T) {
	clock := newClock()
	req := util.NewMockRequestor()
	dst := ds.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust, err := user.NewStore(dst, scs, req, clock.Now)
	require.NoError(t, err)
	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	sc := keys.NewSigchain(alice.ID())
	require.Equal(t, 0, sc.Length())

	usr, err := user.FindUserInSigchain(sc)
	require.NoError(t, err)
	require.Nil(t, usr)

	usr, err = user.NewUser(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewUserSigchainStatement(sc, usr, alice, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	usr, err = user.FindUserInSigchain(sc)
	require.NoError(t, err)
	require.NotNil(t, usr)
	require.Equal(t, "alice", usr.Name)
	require.Equal(t, "github", usr.Service)
	require.Equal(t, "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", usr.URL)
	require.Equal(t, 1, usr.Seq)

	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	usr, err = user.FindUserInSigchain(sc)
	require.NoError(t, err)
	require.Nil(t, usr)

	usr2, err := user.NewUser(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	_, err = user.NewUserSigchainStatement(sc, usr2, alice, clock.Now())
	require.EqualError(t, err, "user seq mismatch")

	usr2, err = user.NewUser(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 3)
	require.NoError(t, err)
	st2, err := user.NewUserSigchainStatement(sc, usr2, alice, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	usr, err = user.FindUserInSigchain(sc)
	require.NoError(t, err)
	require.NotNil(t, usr)
	require.Equal(t, "alice", usr.Name)
	require.Equal(t, "github", usr.Service)
	require.Equal(t, "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", usr.URL)
	require.Equal(t, 3, usr.Seq)
}
