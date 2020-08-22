package user_test

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/stretchr/testify/require"
)

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func testdata(t *testing.T, path string) []byte {
	b, err := ioutil.ReadFile(filepath.Join("..", path))
	require.NoError(t, err)
	b = bytes.ReplaceAll(b, []byte{'\r'}, []byte{})
	return b
}

func TestNewValidate(t *testing.T) {
	var err error
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	_, err = user.New(alice.ID(), "github", "alice", "file://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "invalid scheme for url file://gist.github.com/alice/70281cc427850c272a8574af4d8564d9")

	_, err = user.New(alice.ID(), "github", "alice", "https://githubb.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "invalid host for url https://githubb.com/alice/70281cc427850c272a8574af4d8564d9")

	_, err = user.New(alice.ID(), "github", "alice", "http://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "invalid scheme for url http://gist.github.com/alice/70281cc427850c272a8574af4d8564d9")

	_, err = user.New(alice.ID(), "github", "Alice", "file://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", 1)
	require.EqualError(t, err, "name has an invalid character")
}

func TestSigchainUsers(t *testing.T) {
	clock := tsutil.NewTestClock()

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	sc := keys.NewSigchain(alice.ID())
	require.Equal(t, 0, sc.Length())

	usr, err := user.FindInSigchain(sc)
	require.NoError(t, err)
	require.Nil(t, usr)

	usr, err = user.New(alice.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, usr, alice, clock.Now())
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

	usr2, err := user.New(alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	_, err = user.NewSigchainStatement(sc, usr2, alice, clock.Now())
	require.EqualError(t, err, "user seq mismatch")

	usr2, err = user.New(alice.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 3)
	require.NoError(t, err)
	st2, err := user.NewSigchainStatement(sc, usr2, alice, clock.Now())
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

func TestSignUserVerify(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	u, err := user.NewForSigning(sk.ID(), "github", "gabriel")
	require.NoError(t, err)
	require.NotNil(t, u)

	msg, err := u.Sign(sk)
	require.NoError(t, err)

	usr := &user.User{
		Service: "github",
		KID:     sk.ID(),
		Name:    "gabriel",
	}
	err = user.Verify(msg, usr)
	require.NoError(t, err)
}

func TestUserVerify(t *testing.T) {
	msg := "BEGIN MESSAGE.HWNhu0mATP1TJvQ 2MsM6UREvrdpmJL mlr4taMzxi0olt7 nV35Vkco9gjJ3wyZ0z9hiq2OxrlFUT QVAdNgSZPX3TCKq 6Xr2MZHgg6PbuKB KKAcQRbMCMprx0eQ9AAmF37oSytfuD ekFhesy6sjWc4kJ XA4C6PAxTFwtO14 CEXTYQyBxGH2CYAsm4w2O9xq9TNTZw lo0e7ydqx99UXE8 Qivwr0VNs5.END MESSAGE."
	usr := &user.User{
		Service: "twitter",
		Name:    "gabriel",
		KID:     keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"),
	}
	err := user.Verify(msg, usr)
	require.NoError(t, err)

	usr = &user.User{
		Service: "github",
		Name:    "gabriel",
		KID:     keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"),
	}
	err = user.Verify(msg, usr)
	require.EqualError(t, err, "failed to user verify: service mismatch github != twitter")

	usr = &user.User{
		Service: "twitter",
		Name:    "gabriel2",
		KID:     keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"),
	}
	err = user.Verify(msg, usr)
	require.EqualError(t, err, "failed to user verify: name mismatch gabriel2 != gabriel")

	usr = &user.User{
		Service: "twitter",
		Name:    "gabriel",
		KID:     keys.RandID("test"),
	}
	err = user.Verify(msg, usr)
	require.EqualError(t, err, "failed to user verify: invalid key type for edx25519")

	usr = &user.User{
		Service: "twitter",
		Name:    "gabriel",
		KID:     keys.GenerateEdX25519Key().ID(),
	}
	err = user.Verify(msg, usr)
	require.EqualError(t, err, "failed to user verify: verify failed")
}
