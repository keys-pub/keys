package user_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T, dst docs.Documents, scs keys.SigchainStore, req *request.MockRequestor, clock tsutil.Clock) *user.Store {
	ust, err := user.NewStore(dst, scs, req, clock)
	require.NoError(t, err)
	return ust
}

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

	out, err := user.Verify(msg, sk.ID(), usr)
	require.NoError(t, err)
	require.Equal(t, usr.Service, out.Service)
	require.Equal(t, usr.Name, out.Name)
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

func TestResultGithub(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testStore(t, dst, scs, req, clock)

	req.SetResponse("https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", testdataBytes(t, "testdata/github/70281cc427850c272a8574af4d8564d9"))

	usr, err := user.NewForSigning(sk.ID(), "github", "alice")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)
	_, err = user.Verify(msg, sk.ID(), usr)
	require.NoError(t, err)

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	_, err = user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	result, err := ust.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)
	require.Equal(t, int64(1234567890003), result.VerifiedAt)
	require.Equal(t, int64(1234567890003), result.Timestamp)

	result, err = ust.Get(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	result, err = ust.User(context.TODO(), "alice@github")
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	kids, err := ust.KIDs(context.TODO())
	require.NoError(t, err)
	require.Equal(t, 1, len(kids))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), kids[0])
}

func TestResultGithubWrongName(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testStore(t, dst, scs, req, clock)

	usr, err := user.NewForSigning(sk.ID(), "github", "alice2")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf(msg)

	sc := keys.NewSigchain(sk.ID())
	req.SetResponse("https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", testdataBytes(t, "testdata/github/a7b1370270e2672d4ae88fa5d0c6ade7"))
	user2, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	b2, err := json.Marshal(user2)
	require.NoError(t, err)
	st2, err := keys.NewSigchainStatement(sc, b2, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	result, err := ust.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusStatementInvalid, result.Status)
	require.Equal(t, result.Err, "name mismatch alice != alice2")
}

func TestResultGithubWrongService(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testStore(t, dst, scs, req, clock)
	sc := keys.NewSigchain(sk.ID())

	muser := &user.User{KID: sk.ID(), Service: "github2", Name: "gabriel"}
	msg, err := muser.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	req.SetResponse("https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", testdataBytes(t, "testdata/github/bd679134acba688cbcc0a65fa0890d76"))
	usr, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", 1)
	require.NoError(t, err)
	b, err := json.Marshal(usr)
	require.NoError(t, err)
	st, err := keys.NewSigchainStatement(sc, b, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	result, err := ust.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusStatementInvalid, result.Status)
	require.Equal(t, result.Err, "service mismatch github != github2")
}

func TestResultTwitter(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testStore(t, dst, scs, req, clock)

	usr, err := user.NewForSigning(sk.ID(), "twitter", "bob")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "twitter", "bob", "https://twitter.com/bob/status/1205589994380783616", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	_, err = user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	req.SetResponse("https://mobile.twitter.com/bob/status/1205589994380783616", testdataBytes(t, "testdata/twitter/1205589994380783616"))

	result, err := ust.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "twitter", result.User.Service)
	require.Equal(t, "bob", result.User.Name)
	require.Equal(t, int64(1234567890003), result.VerifiedAt)
	require.Equal(t, int64(1234567890003), result.Timestamp)
}

func TestResultReddit(t *testing.T) {
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))
	// services.SetLogger(keys.NewLogger(keys.DebugLevel))

	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testStore(t, dst, scs, req, clock)

	usr, err := user.NewForSigning(sk.ID(), "reddit", "charlie")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "reddit", "charlie", "https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/charlie/", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	_, err = user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	req.SetResponse("https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/charlie.json", testdataBytes(t, "testdata/reddit/charlie.json"))

	result, err := ust.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "reddit", result.User.Service)
	require.Equal(t, "charlie", result.User.Name)
	require.Equal(t, int64(1234567890003), result.VerifiedAt)
	require.Equal(t, int64(1234567890003), result.Timestamp)
}

func TestUserUnverified(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "twitter", "bob", "https://twitter.com/bob/status/1", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	req.SetError("https://mobile.twitter.com/bob/status/1", errors.Errorf("testing"))
	require.NoError(t, err)

	// users, err := ust.Update(context.TODO(), sk.ID())
	// require.NoError(t, err)
	// t.Logf("users: %+v", users)
	// TODO: Finish test
}

func TestCheckNoUsers(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc := keys.NewSigchain(sk.ID())

	req := request.NewMockRequestor()
	clock := tsutil.NewTestClock()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testStore(t, dst, scs, req, clock)

	result, err := ust.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Nil(t, result)

	rk := keys.GenerateEdX25519Key()
	result, err = ust.Update(context.TODO(), rk.ID())
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestCheckFailure(t *testing.T) {
	req := request.NewMockRequestor()
	clock := tsutil.NewTestClock()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	ust := testStore(t, dst, scs, req, clock)

	msg := "BEGIN MESSAGE.HWNhu0mATP1TJvQ 2MsM6UREvrdpmJL mlr4taMzxi0olt7 nV35Vkco9gjJ3wyZ0z9hiq2OxrlFUT QVAdNgSZPX3TCKq 6Xr2MZHgg6PbuKB KKAcQRbMCMprx0eQ9AAmF37oSytfuD ekFhesy6sjWc4kJ XA4C6PAxTFwtO14 CEXTYQyBxGH2CYAsm4w2O9xq9TNTZw lo0e7ydqx99UXE8 Qivwr0VNs5.END MESSAGE."
	req.SetResponse("https://mobile.twitter.com/boboloblaw/status/1259188857846632448", []byte(msg))

	usr := &user.User{
		Name:    "gabriel",
		KID:     keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"),
		Seq:     1,
		Service: "twitter",
		URL:     "https://twitter.com/boboloblaw/status/1259188857846632448",
	}
	result := ust.RequestVerify(context.TODO(), usr)
	require.Equal(t, usr.Name, result.User.Name)
	require.Equal(t, result.Status, user.StatusFailure)
	require.Equal(t, result.Err, "path invalid (name mismatch) for url https://twitter.com/boboloblaw/status/1259188857846632448")
}

func TestVerify(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	u, uerr := user.NewForSigning(sk.ID(), "github", "gabriel")
	require.NoError(t, uerr)
	require.NotNil(t, u)

	msg, err := u.Sign(sk)
	require.NoError(t, err)

	uout, err := user.Verify(msg, sk.ID(), nil)
	require.NoError(t, err)

	require.Equal(t, "gabriel", uout.Name)
	require.Equal(t, "github", uout.Service)
	require.Equal(t, sk.ID(), uout.KID)

	_, err = user.Verify(msg, sk.ID(), uout)
	require.NoError(t, err)
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

func TestSigchainUserStoreUpdate(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	// link.SetLogger(link.NewLogger(link.DebugLevel))

	b := []byte(`{".sig":"5NUJkMad0hNC6Xy3bJGmTHkaDjRIH6IWWpLdwf2qrrZI2NNEHb8+Hf4YxDgTcEA/Q5FsUJxkslrksVCRBYTEAw==","data":"eyJrIjoia2V4MWQ2OWc3bXpqam44Y2ZtM3NzZHI5dTh6OG1oMmQzNWN2anpzcndybmR0NGQwMDZ1aGg2OXF5eDJrNXgiLCJuIjoiZ2FicmllbCIsInNxIjoxLCJzciI6InR3aXR0ZXIiLCJ1IjoiaHR0cHM6Ly90d2l0dGVyLmNvbS9nYWJyaWVsL3N0YXR1cy8xMjU5MTg4ODU3ODQ2NjMyNDQ4In0=","kid":"kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x","seq":1,"ts":1589049007370,"type":"user"}`)

	kid := keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x")
	sc := keys.NewSigchain(kid)

	var st keys.Statement
	err := json.Unmarshal(b, &st)
	require.NoError(t, err)

	err = sc.Add(&st)
	require.NoError(t, err)

	clock := tsutil.NewTestClock()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	req := request.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)

	msg := "BEGIN MESSAGE.HWNhu0mATP1TJvQ 2MsM6UREvrdpmJL mlr4taMzxi0olt7 nV35Vkco9gjJ3wyZ0z9hiq2OxrlFUT QVAdNgSZPX3TCKq 6Xr2MZHgg6PbuKB KKAcQRbMCMprx0eQ9AAmF37oSytfuD ekFhesy6sjWc4kJ XA4C6PAxTFwtO14 CEXTYQyBxGH2CYAsm4w2O9xq9TNTZw lo0e7ydqx99UXE8 Qivwr0VNs5.END MESSAGE."
	req.SetResponse("https://mobile.twitter.com/gabriel/status/1259188857846632448", []byte(msg))

	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	result, err := ust.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, result.Status)
}

func TestSigchainRevokeUpdate(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	clock := tsutil.NewTestClock()
	dst := docs.NewMem()
	scs := keys.NewSigchainStore(dst)
	req := request.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)

	sk := keys.GenerateEdX25519Key()
	kid := sk.ID()
	sc := keys.NewSigchain(kid)

	// Update
	usr, err := user.NewForSigning(kid, "twitter", "gabriel")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)

	stu, err := user.New(kid, "twitter", "gabriel", "https://mobile.twitter.com/gabriel/status/1", 1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	req.SetResponse("https://mobile.twitter.com/gabriel/status/1", []byte(msg))

	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	result, err := ust.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, result.Status)

	// Revoke
	_, err = sc.Revoke(1, sk)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	// Don't update here to test revoke + new statement updates correctly

	// Update #2
	stu2, err := user.New(kid, "twitter", "gabriel", "https://mobile.twitter.com/gabriel/status/2", 3)
	require.NoError(t, err)
	st2, err := user.NewSigchainStatement(sc, stu2, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	req.SetResponse("https://mobile.twitter.com/gabriel/status/2", []byte(msg))

	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	result, err = ust.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
}
