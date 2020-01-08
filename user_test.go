package keys

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func testUserStore(t *testing.T, dst DocumentStore, scs SigchainStore, req *MockRequestor, clock *clock) *UserStore {
	ust, err := NewUserStore(dst, scs, []string{Twitter, Github}, req, clock.Now)
	require.NoError(t, err)
	return ust
}

func TestNewUserForTwitterSigning(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	req := NewMockRequestor()
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)
	user, err := NewUserForSigning(ust, sk.ID(), Twitter, "123456789012345")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
	require.NoError(t, err)
	expected := `BEGIN MESSAGE.
iDAzaNexn2Pyskw kN7nPOqHMaHQAW6 eCKdqqPJjRvSYR8 nWsd3L6xJbPObZ9
L25BID9V4AZbluY BNeXrpYoOeATCKq 6Xr2MZlres4noBA pBkewkEz5593DxH
Pj84f5pY7PE1JEq D2gGjkgLByR9CFG 2aCgRgZZwl5UAa4 6bmBzOcQByOYlKb
OS0ciNjMXqme7oU c8SlPAP9Gq3SDMQ Dg7eM5fLogY3MDW UqhLx.
END MESSAGE.`
	require.Equal(t, expected, msg)
	require.False(t, len(msg) > 280)
	require.Equal(t, 274, len(msg))

	out, err := VerifyUser(msg, sk.PublicKey(), user)
	require.NoError(t, err)
	require.Equal(t, user.Service, out.Service)
	require.Equal(t, user.Name, out.Name)
}

func TestNewUserMarshal(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	req := NewMockRequestor()
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)
	user, err := NewUser(ust, sk.ID(), Twitter, "123456789012345", "https://twitter.com/123456789012345/status/1234567890", 1)
	require.NoError(t, err)
	b, err := json.Marshal(user)
	require.NoError(t, err)
	require.Equal(t, `{"k":"kpe132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqlrnuen","n":"123456789012345","sq":1,"sr":"twitter","u":"https://twitter.com/123456789012345/status/1234567890"}`, string(b))

	var userOut User
	err = json.Unmarshal(b, &userOut)
	require.NoError(t, err)
	require.Equal(t, user.Name, userOut.Name)
	require.Equal(t, user.Seq, userOut.Seq)
	require.Equal(t, user.KID, userOut.KID)
	require.Equal(t, user.Service, userOut.Service)
	require.Equal(t, user.URL, userOut.URL)

	user, err = NewUserForSigning(ust, sk.ID(), Twitter, "123456789012345")
	require.NoError(t, err)
	b, err = json.Marshal(user)
	require.NoError(t, err)
	require.Equal(t, `{"k":"kpe132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqlrnuen","n":"123456789012345","sr":"twitter"}`, string(b))
}

func TestUserResultGithub(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	clock := newClock()
	req := NewMockRequestor()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	err = req.SetResponseFile("https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", "testdata/github/70281cc427850c272a8574af4d8564d9")
	require.NoError(t, err)

	user, err := NewUserForSigning(ust, sk.ID(), "github", "alice")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)
	_, err = VerifyUser(msg, sk.PublicKey(), user)
	require.NoError(t, err)

	sc := NewSigchain(sk.PublicKey())
	stu, err := NewUser(ust, sk.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	_, err = GenerateUserStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	results, err := ust.checkSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, UserStatusOK, results[0].Status)
	require.Equal(t, "github", results[0].User.Service)
	require.Equal(t, "alice", results[0].User.Name)
	require.Equal(t, TimeMs(1234567890004), results[0].VerifiedAt)
	require.Equal(t, TimeMs(1234567890003), results[0].Timestamp)
}

func TestUserResultGithubWrongName(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	clock := newClock()
	req := NewMockRequestor()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	user, err := NewUserForSigning(ust, sk.ID(), "github", "alice2")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf(msg)

	sc := NewSigchain(sk.PublicKey())
	err = req.SetResponseFile("https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", "testdata/github/a7b1370270e2672d4ae88fa5d0c6ade7")
	require.NoError(t, err)
	user2, err := NewUser(ust, sk.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	b2, err := json.Marshal(user2)
	require.NoError(t, err)
	st2, err := GenerateStatement(sc, b2, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	users, err := ust.checkSigchain(context.TODO(), sc)
	require.Equal(t, 1, len(users))
	require.Equal(t, UserStatusFailure, users[0].Status)
	require.Equal(t, users[0].Err, "name mismatch alice != alice2")
}

func TestUserResultGithubWrongService(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	clock := newClock()
	req := NewMockRequestor()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)
	sc := NewSigchain(sk.PublicKey())

	muser := &User{KID: sk.ID(), Service: "github2", Name: "gabriel"}
	msg, err := muser.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	err = req.SetResponseFile("https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", "testdata/github/bd679134acba688cbcc0a65fa0890d76")
	require.NoError(t, err)
	user, err := NewUser(ust, sk.ID(), "github", "alice", "https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", 1)
	require.NoError(t, err)
	b, err := json.Marshal(user)
	require.NoError(t, err)
	st, err := GenerateStatement(sc, b, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	users, err := ust.checkSigchain(context.TODO(), sc)
	require.Equal(t, 1, len(users))
	require.Equal(t, UserStatusFailure, users[0].Status)
	require.Equal(t, users[0].Err, "service mismatch github != github2")
}

func TestUserResultTwitter(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	clock := newClock()
	req := NewMockRequestor()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	user, err := NewUserForSigning(ust, sk.ID(), Twitter, "bob")
	require.NoError(t, err)
	msg, err := user.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	sc := NewSigchain(sk.PublicKey())
	stu, err := NewUser(ust, sk.ID(), Twitter, "bob", "https://twitter.com/bob/status/1205589994380783616", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	_, err = GenerateUserStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	err = req.SetResponseFile("https://twitter.com/bob/status/1205589994380783616", "testdata/twitter/1205589994380783616")
	require.NoError(t, err)

	users, err := ust.checkSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Equal(t, 1, len(users))
	require.NotNil(t, users[0].User)
	require.Equal(t, UserStatusOK, users[0].Status)
	require.Equal(t, Twitter, users[0].User.Service)
	require.Equal(t, "bob", users[0].User.Name)
	require.Equal(t, TimeMs(1234567890004), users[0].VerifiedAt)
	require.Equal(t, TimeMs(1234567890003), users[0].Timestamp)
}

func TestUserUnverified(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	clock := newClock()
	req := NewMockRequestor()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	sc := NewSigchain(sk.PublicKey())
	stu, err := NewUser(ust, sk.ID(), Twitter, "bob", "https://twitter.com/bob/status/1", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	req.SetError("https://twitter.com/bob/status/1", errors.Errorf("testing"))
	require.NoError(t, err)

	users, err := ust.checkSigchain(context.TODO(), sc)
	require.NoError(t, err)
	t.Logf("users: %+v", users)
	// TODO: Fix test
}

func TestCheckNoUsers(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)
	sc := NewSigchain(sk.PublicKey())

	req := NewMockRequestor()
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	users, err := ust.checkSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Equal(t, 0, len(users))

	rk := GenerateSignKey()
	res, err := ust.Update(context.TODO(), rk.ID())
	require.NoError(t, err)
	require.Equal(t, 0, len(res))
}

func TestVerifyUser(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	req := NewMockRequestor()
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	ust := testUserStore(t, dst, scs, req, clock)

	u, uerr := NewUserForSigning(ust, sk.ID(), "github", "gabriel")
	require.NoError(t, uerr)
	require.NotNil(t, u)

	msg, err := u.Sign(sk)
	require.NoError(t, err)

	uout, err := VerifyUser(msg, sk.PublicKey(), nil)
	require.NoError(t, err)

	require.Equal(t, "gabriel", uout.Name)
	require.Equal(t, "github", uout.Service)
	require.Equal(t, sk.ID(), uout.KID)

	_, err = VerifyUser(msg, sk.PublicKey(), uout)
	require.NoError(t, err)
}

func TestNewUser(t *testing.T) {
	sk, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	req := NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)

	u, uerr := NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u)

	u2, uerr := NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.githb.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid host for url https://gist.githb.com/gabriel/deadbeef")
	require.Nil(t, u2)

	u3, uerr := NewUser(ust, sk.ID(), "github", "gabriel", "http://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid scheme for url http://gist.github.com/gabriel/deadbeef")
	require.Nil(t, u3)

	u4, uerr := NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.github.com/gabril/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabril != gabriel")
	require.Nil(t, u4)

	u5, uerr := NewUser(ust, sk.ID(), "github", "gabriel", "https://gist.github.com/gabriel", 1)
	require.EqualError(t, uerr, "path invalid [gabriel] for url https://gist.github.com/gabriel")
	require.Nil(t, u5)

	u6, uerr := NewUser(ust, sk.ID(), "github", "gab", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "path invalid (name mismatch) gabriel != gab")
	require.Nil(t, u6)

	u7, uerr := NewUser(ust, sk.ID(), "git", "gabriel", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "invalid service git")
	require.Nil(t, u7)

	u8, uerr := NewUser(ust, sk.ID(), "github", "", "https://gist.github.com/gabriel/deadbeef", 1)
	require.EqualError(t, uerr, "name is empty")
	require.Nil(t, u8)

	u9, uerr := NewUser(ust, sk.ID(), Twitter, "@gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.NoError(t, uerr)
	require.NotNil(t, u9)
	require.Equal(t, "gbrltest", u9.Name)

	u10, uerr0 := NewUser(ust, sk.ID(), Twitter, "Gbrltest", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr0, "user name should be lowercase")
	require.Nil(t, u10)

	u11, uerr1 := NewUser(ust, sk.ID(), Twitter, "gbrltest🤓", "https://twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr1, "user name has non-ASCII characters")
	require.Nil(t, u11)

	u12, uerr := NewUser(ust, sk.ID(), Twitter, "gbrltest", "twitter.com/gbrltest/status/1234", 1)
	require.EqualError(t, uerr, "invalid scheme for url twitter.com/gbrltest/status/1234")
	require.Nil(t, u12)
}
