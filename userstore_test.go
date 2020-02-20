package keys_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func testUserStore(t *testing.T, dst keys.DocumentStore, scs keys.SigchainStore, req *keys.MockRequestor, clock *clock) *keys.UserStore {
	ust, err := keys.NewUserStore(dst, scs, []string{keys.Twitter, keys.Github}, req, clock.Now)
	require.NoError(t, err)
	return ust
}

func TestNewUserForTwitterSigning(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	req := keys.NewMockRequestor()
	clock := newClock()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)
	user, err := keys.NewUserForSigning(ust, sk.ID(), keys.Twitter, "123456789012345")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
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

	out, err := keys.VerifyUser(msg, sk.PublicKey(), user)
	require.NoError(t, err)
	require.Equal(t, user.Service, out.Service)
	require.Equal(t, user.Name, out.Name)
}

func TestNewUserMarshal(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	req := keys.NewMockRequestor()
	clock := newClock()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)
	user, err := keys.NewUser(ust, sk.ID(), keys.Twitter, "123456789012345", "https://twitter.com/123456789012345/status/1234567890", 1)
	require.NoError(t, err)
	b, err := json.Marshal(user)
	require.NoError(t, err)
	require.Equal(t, `{"k":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","n":"123456789012345","sq":1,"sr":"twitter","u":"https://twitter.com/123456789012345/status/1234567890"}`, string(b))

	var userOut keys.User
	err = json.Unmarshal(b, &userOut)
	require.NoError(t, err)
	require.Equal(t, user.Name, userOut.Name)
	require.Equal(t, user.Seq, userOut.Seq)
	require.Equal(t, user.KID, userOut.KID)
	require.Equal(t, user.Service, userOut.Service)
	require.Equal(t, user.URL, userOut.URL)

	user, err = keys.NewUserForSigning(ust, sk.ID(), keys.Twitter, "123456789012345")
	require.NoError(t, err)
	b, err = json.Marshal(user)
	require.NoError(t, err)
	require.Equal(t, `{"k":"kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077","n":"123456789012345","sr":"twitter"}`, string(b))
}

func TestUserResultGithub(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	clock := newClock()
	req := keys.NewMockRequestor()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	err := req.SetResponseFile("https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", "testdata/github/70281cc427850c272a8574af4d8564d9")
	require.NoError(t, err)

	user, err := keys.NewUserForSigning(ust, sk.ID(), "github", "alice")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)
	_, err = keys.VerifyUser(msg, sk.PublicKey(), user)
	require.NoError(t, err)

	sc := keys.NewSigchain(sk.PublicKey())
	stu, err := keys.NewUser(ust, sk.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := keys.GenerateUserStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	_, err = keys.GenerateUserStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	result, err := ust.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, keys.UserStatusOK, result.Status)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)
	require.Equal(t, keys.TimeMs(1234567890004), result.VerifiedAt)
	require.Equal(t, keys.TimeMs(1234567890003), result.Timestamp)

	result, err = ust.Get(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	result, err = ust.User(context.TODO(), "alice@github")
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)
}

func TestUserResultGithubWrongName(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	clock := newClock()
	req := keys.NewMockRequestor()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	user, err := keys.NewUserForSigning(ust, sk.ID(), "github", "alice2")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf(msg)

	sc := keys.NewSigchain(sk.PublicKey())
	err = req.SetResponseFile("https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", "testdata/github/a7b1370270e2672d4ae88fa5d0c6ade7")
	require.NoError(t, err)
	user2, err := keys.NewUser(ust, sk.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	b2, err := json.Marshal(user2)
	require.NoError(t, err)
	st2, err := keys.GenerateStatement(sc, b2, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	result, err := ust.CheckSigchain(context.TODO(), sc)
	require.NotNil(t, result)
	require.Equal(t, keys.UserStatusFailure, result.Status)
	require.Equal(t, result.Err, "name mismatch alice != alice2")
}

func TestUserResultGithubWrongService(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	clock := newClock()
	req := keys.NewMockRequestor()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)
	sc := keys.NewSigchain(sk.PublicKey())

	muser := &keys.User{KID: sk.ID(), Service: "github2", Name: "gabriel"}
	msg, err := muser.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	err = req.SetResponseFile("https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", "testdata/github/bd679134acba688cbcc0a65fa0890d76")
	require.NoError(t, err)
	user, err := keys.NewUser(ust, sk.ID(), "github", "alice", "https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", 1)
	require.NoError(t, err)
	b, err := json.Marshal(user)
	require.NoError(t, err)
	st, err := keys.GenerateStatement(sc, b, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	result, err := ust.CheckSigchain(context.TODO(), sc)
	require.NotNil(t, result)
	require.Equal(t, keys.UserStatusFailure, result.Status)
	require.Equal(t, result.Err, "service mismatch github != github2")
}

func TestUserResultTwitter(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	clock := newClock()
	req := keys.NewMockRequestor()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	user, err := keys.NewUserForSigning(ust, sk.ID(), keys.Twitter, "bob")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	sc := keys.NewSigchain(sk.PublicKey())
	stu, err := keys.NewUser(ust, sk.ID(), keys.Twitter, "bob", "https://twitter.com/bob/status/1205589994380783616", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := keys.GenerateUserStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	_, err = keys.GenerateUserStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	err = req.SetResponseFile("https://twitter.com/bob/status/1205589994380783616", "testdata/twitter/1205589994380783616")
	require.NoError(t, err)

	result, err := ust.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, keys.UserStatusOK, result.Status)
	require.Equal(t, keys.Twitter, result.User.Service)
	require.Equal(t, "bob", result.User.Name)
	require.Equal(t, keys.TimeMs(1234567890004), result.VerifiedAt)
	require.Equal(t, keys.TimeMs(1234567890003), result.Timestamp)
}

func TestUserUnverified(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	clock := newClock()
	req := keys.NewMockRequestor()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	sc := keys.NewSigchain(sk.PublicKey())
	stu, err := keys.NewUser(ust, sk.ID(), keys.Twitter, "bob", "https://twitter.com/bob/status/1", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := keys.GenerateUserStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	req.SetError("https://twitter.com/bob/status/1", errors.Errorf("testing"))
	require.NoError(t, err)

	users, err := ust.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	t.Logf("users: %+v", users)
	// TODO: Fix test
}

func TestCheckNoUsers(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	sc := keys.NewSigchain(sk.PublicKey())

	req := keys.NewMockRequestor()
	clock := newClock()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	result, err := ust.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Nil(t, result)

	rk := keys.GenerateEdX25519Key()
	result, err = ust.Update(context.TODO(), rk.ID())
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestVerifyUser(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	req := keys.NewMockRequestor()
	clock := newClock()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	u, uerr := keys.NewUserForSigning(ust, sk.ID(), "github", "gabriel")
	require.NoError(t, uerr)
	require.NotNil(t, u)

	msg, err := u.Sign(sk)
	require.NoError(t, err)

	uout, err := keys.VerifyUser(msg, sk.PublicKey(), nil)
	require.NoError(t, err)

	require.Equal(t, "gabriel", uout.Name)
	require.Equal(t, "github", uout.Service)
	require.Equal(t, sk.ID(), uout.KID)

	_, err = keys.VerifyUser(msg, sk.PublicKey(), uout)
	require.NoError(t, err)
}

func TestNewUser(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	clock := newClock()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	req := keys.NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)

	u, uerr := keys.NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u)

	u2, uerr := keys.NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.githb.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid host for url https://gist.githb.com/gabriel/deadbeef")
	require.Nil(t, u2)

	u3, uerr := keys.NewUser(ust, sk.ID(), "github", "gabriel", "http://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid scheme for url http://gist.github.com/gabriel/deadbeef")
	require.Nil(t, u3)

	u4, uerr := keys.NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.github.com/gabril/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabril != gabriel")
	require.Nil(t, u4)

	u5, uerr := keys.NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.github.com/gabriel", 1)
	require.EqualError(t, uerr, "path invalid [gabriel] for url https://gist.github.com/gabriel")
	require.Nil(t, u5)

	u6, uerr := keys.NewUser(ust, sk.ID(), "github", "gab", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabriel != gab")
	require.Nil(t, u6)

	u7, uerr := keys.NewUser(ust, sk.ID(), "git", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid service git")
	require.Nil(t, u7)

	u8, uerr := keys.NewUser(ust, sk.ID(), "github", "", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "name is empty")
	require.Nil(t, u8)

	u9, uerr := keys.NewUser(ust, sk.ID(), keys.Twitter, "@gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u9)
	require.Equal(t, "gbrltest", u9.Name)

	u10, uerr0 := keys.NewUser(ust, sk.ID(), keys.Twitter, "Gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr0, "user name should be lowercase")
	require.Nil(t, u10)

	u11, uerr1 := keys.NewUser(ust, sk.ID(), keys.Twitter, "gbrltest🤓", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr1, "user name has non-ASCII characters")
	require.Nil(t, u11)

	u12, uerr := keys.NewUser(ust, sk.ID(), keys.Twitter, "gbrltest", "twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr, "invalid scheme for url twitter.com/gbrltest/status/1234")
	require.Nil(t, u12)
}
