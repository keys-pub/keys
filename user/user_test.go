package user_test

import (
	"bytes"
	"encoding/json"
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

func TestNewUserMarshal(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	usr, err := user.New(sk.ID(), "twitter", "123456789012345", "https://twitter.com/123456789012345/status/1234567890", 1)
	require.NoError(t, err)
	b, err := json.Marshal(usr)
	require.NoError(t, err)
	require.Equal(t, `{"k":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","n":"123456789012345","sq":1,"sr":"twitter","u":"https://twitter.com/123456789012345/status/1234567890"}`, string(b))

	var usrOut user.User
	err = json.Unmarshal(b, &usrOut)
	require.NoError(t, err)
	require.Equal(t, usr.Name, usrOut.Name)
	require.Equal(t, usr.Seq, usrOut.Seq)
	require.Equal(t, usr.KID, usrOut.KID)
	require.Equal(t, usr.Service, usrOut.Service)
	require.Equal(t, usr.URL, usrOut.URL)

	usr, err = user.NewForSigning(sk.ID(), "twitter", "123456789012345")
	require.NoError(t, err)
	b, err = json.Marshal(usr)
	require.NoError(t, err)
	require.Equal(t, `{"k":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","n":"123456789012345","sr":"twitter"}`, string(b))
}

func TestSigchainUsers(t *testing.T) {
	clock := tsutil.NewTestClock()

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	sc := keys.NewSigchain(alice.ID())
	require.Equal(t, 0, sc.Length())

	users, err := user.FindInSigchain(sc)
	require.NoError(t, err)
	require.Equal(t, 0, len(users))

	usr, err := user.New(alice.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, usr, alice, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	users, err = user.FindInSigchain(sc)
	require.NoError(t, err)
	require.Equal(t, 1, len(users))
	require.Equal(t, "alice", users[0].Name)
	require.Equal(t, "github", users[0].Service)
	require.Equal(t, "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", users[0].URL)
	require.Equal(t, 1, users[0].Seq)

	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	users, err = user.FindInSigchain(sc)
	require.NoError(t, err)
	require.Equal(t, 0, len(users))

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

	users, err = user.FindInSigchain(sc)
	require.NoError(t, err)
	require.Equal(t, 1, len(users))
	require.Equal(t, "alice", users[0].Name)
	require.Equal(t, "github", users[0].Service)
	require.Equal(t, "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", users[0].URL)
	require.Equal(t, 3, users[0].Seq)
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

func TestNewUser(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	u, uerr := user.New(sk.ID(), "github", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u)

	u2, uerr := user.New(sk.ID(), "github", "gabriel", "https://gist.githb.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid host for url https://gist.githb.com/gabriel/deadbeef")
	require.Nil(t, u2)

	u3, uerr := user.New(sk.ID(), "github", "gabriel", "http://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid scheme for url http://gist.github.com/gabriel/deadbeef")
	require.Nil(t, u3)

	u4, uerr := user.New(sk.ID(), "github", "gabriel", "https://gist.github.com/gabril/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabril != gabriel")
	require.Nil(t, u4)

	u5, uerr := user.New(sk.ID(), "github", "gabriel", "https://gist.github.com/gabriel", 1)
	require.EqualError(t, uerr, "path invalid [gabriel] for url https://gist.github.com/gabriel")
	require.Nil(t, u5)

	u6, uerr := user.New(sk.ID(), "github", "gab", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabriel != gab")
	require.Nil(t, u6)

	u7, uerr := user.New(sk.ID(), "git", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid service git")
	require.Nil(t, u7)

	u8, uerr := user.New(sk.ID(), "github", "", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "name is empty")
	require.Nil(t, u8)

	u10, uerr := user.New(sk.ID(), "twitter", "Gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr, "name has an invalid character")
	require.Nil(t, u10)

	u11, uerr := user.New(sk.ID(), "twitter", "gbrltest🤓", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr, "name has an invalid character")
	require.Nil(t, u11)

	u12, uerr := user.New(sk.ID(), "twitter", "gbrltest", "twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr, "invalid scheme for url twitter.com/gbrltest/status/1234")
	require.Nil(t, u12)
}
