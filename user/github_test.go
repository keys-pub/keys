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
	"github.com/stretchr/testify/require"
)

func TestResultGithub(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	req.SetResponse("https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", testdata(t, "testdata/github/70281cc427850c272a8574af4d8564d9"))

	usr, err := user.NewForSigning(sk.ID(), "github", "alice")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)
	err = user.Verify(msg, usr)
	require.NoError(t, err)

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/70281cc427850c272a8574af4d8564d9", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	_, err = user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	result, err := users.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)
	require.Equal(t, int64(1234567890003), result.VerifiedAt)
	require.Equal(t, int64(1234567890003), result.Timestamp)

	result, err = users.Get(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	result, err = users.User(context.TODO(), "alice@github")
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	kids, err := users.KIDs(context.TODO())
	require.NoError(t, err)
	require.Equal(t, 1, len(kids))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), kids[0])

	res, err := users.Search(context.TODO(), &user.SearchRequest{Query: "alice"})
	require.NoError(t, err)
	require.Equal(t, 1, len(res))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), res[0].KID)
}

func TestResultGithubWrongName(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	usr, err := user.NewForSigning(sk.ID(), "github", "alice2")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf(msg)

	sc := keys.NewSigchain(sk.ID())
	req.SetResponse("https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", testdata(t, "testdata/github/a7b1370270e2672d4ae88fa5d0c6ade7"))
	user2, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/a7b1370270e2672d4ae88fa5d0c6ade7", 1)
	require.NoError(t, err)
	b2, err := json.Marshal(user2)
	require.NoError(t, err)
	st2, err := keys.NewSigchainStatement(sc, b2, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	result, err := users.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusStatementInvalid, result.Status)
	require.Equal(t, result.Err, "failed to user verify: name mismatch alice != alice2")
}

func TestResultGithubWrongService(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))
	sc := keys.NewSigchain(sk.ID())

	muser := &user.User{KID: sk.ID(), Service: "github2", Name: "gabriel"}
	msg, err := muser.Sign(sk)
	require.NoError(t, err)
	t.Logf(msg)

	req.SetResponse("https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", testdata(t, "testdata/github/bd679134acba688cbcc0a65fa0890d76"))
	usr, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/bd679134acba688cbcc0a65fa0890d76", 1)
	require.NoError(t, err)
	b, err := json.Marshal(usr)
	require.NoError(t, err)
	st, err := keys.NewSigchainStatement(sc, b, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	result, err := users.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusStatementInvalid, result.Status)
	require.Equal(t, result.Err, "failed to user verify: service mismatch github != github2")
}
