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

func TestNewValidate(t *testing.T) {
	clock := newClock()
	req := util.NewMockRequestor()
	dst := ds.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust, err := user.NewStore(dst, scs, req, clock.Now)
	require.NoError(t, err)
	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	_, err = user.New(ust, alice.ID(), "github", "alice", "file://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "invalid scheme for url file://gist.github.com/alice/70281cc427850c272a8574af4d8564d9")

	_, err = user.New(ust, alice.ID(), "github", "alice", "https://githubb.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "invalid host for url https://githubb.com/alice/70281cc427850c272a8574af4d8564d9")

	_, err = user.New(ust, alice.ID(), "github", "alice", "http://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "invalid scheme for url http://gist.github.com/alice/70281cc427850c272a8574af4d8564d9")

	_, err = user.New(ust, alice.ID(), "github", "Alice", "file://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "name has an invalid character")
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

	usr, err := user.FindInSigchain(sc)
	require.NoError(t, err)
	require.Nil(t, usr)

	usr, err = user.New(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewUserSigchainStatement(sc, usr, alice, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	usr, err = user.FindInSigchain(sc)
	require.NoError(t, err)
	require.NotNil(t, usr)
	require.Equal(t, "alice", usr.Name)
	require.Equal(t, "github", usr.Service)
	require.Equal(t, "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", usr.URL)
	require.Equal(t, 1, usr.Seq)

	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	usr, err = user.FindInSigchain(sc)
	require.NoError(t, err)
	require.Nil(t, usr)

	usr2, err := user.New(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	_, err = user.NewUserSigchainStatement(sc, usr2, alice, clock.Now())
	require.EqualError(t, err, "user seq mismatch")

	usr2, err = user.New(ust, alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 3)
	require.NoError(t, err)
	st2, err := user.NewUserSigchainStatement(sc, usr2, alice, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	usr, err = user.FindInSigchain(sc)
	require.NoError(t, err)
	require.NotNil(t, usr)
	require.Equal(t, "alice", usr.Name)
	require.Equal(t, "github", usr.Service)
	require.Equal(t, "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", usr.URL)
	require.Equal(t, 3, usr.Seq)
}

func TestUserVerify(t *testing.T) {
	msg := "BEGIN MESSAGE.HWNhu0mATP1TJvQ 2MsM6UREvrdpmJL mlr4taMzxi0olt7 nV35Vkco9gjJ3wyZ0z9hiq2OxrlFUT QVAdNgSZPX3TCKq 6Xr2MZHgg6PbuKB KKAcQRbMCMprx0eQ9AAmF37oSytfuD ekFhesy6sjWc4kJ XA4C6PAxTFwtO14 CEXTYQyBxGH2CYAsm4w2O9xq9TNTZw lo0e7ydqx99UXE8 Qivwr0VNs5.END MESSAGE."
	usr := &user.User{
		Name:    "gabriel",
		KID:     keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"),
		Seq:     1,
		Service: "twitter",
		URL:     "https://twitter.com/gabriel/status/1259188857846632448",
	}
	out, err := user.Verify(msg, keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"), usr)
	require.NoError(t, err)

	require.Equal(t, usr.KID, out.KID)
	require.Equal(t, usr.Name, out.Name)
	require.Equal(t, usr.Service, out.Service)
}
