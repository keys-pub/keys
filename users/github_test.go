package users_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/users"
	"github.com/stretchr/testify/require"
)

func TestResultGithub(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Clock(clock))

	usr, err := user.NewForSigning(sk.ID(), "github", "alice")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)

	err = usr.Verify(msg)
	require.NoError(t, err)

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/1", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	_, err = user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	usrs.Client().SetProxy("", func(ctx context.Context, req *http.Request, headers []http.Header) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(githubMock("alice", "1", msg))}
	})

	result, err := usrs.Update(context.TODO(), sk.ID(), nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)
	require.Equal(t, int64(1234567890003), result.VerifiedAt)
	require.Equal(t, int64(1234567890003), result.Timestamp)

	result, err = usrs.Get(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	result, err = usrs.User(context.TODO(), "alice@github")
	require.NoError(t, err)
	require.Equal(t, "github", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	kids, err := usrs.KIDs(context.TODO())
	require.NoError(t, err)
	require.Equal(t, 1, len(kids))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), kids[0])

	res, err := usrs.Search(context.TODO(), &users.SearchRequest{Query: "alice"})
	require.NoError(t, err)
	require.Equal(t, 1, len(res))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), res[0].KID)
}

func TestResultGithubWrongName(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Clock(clock))

	usr, err := user.NewForSigning(sk.ID(), "github", "alice2")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	require.NotEqual(t, "", msg)
	t.Logf(msg)

	sc := keys.NewSigchain(sk.ID())

	usrs.Client().SetProxy("", func(ctx context.Context, req *http.Request, headers []http.Header) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(githubMock("alice", "1", msg))}
	})

	user2, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/1", 1)
	require.NoError(t, err)
	b2, err := json.Marshal(user2)
	require.NoError(t, err)
	st2, err := keys.NewSigchainStatement(sc, b2, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	result, err := usrs.CheckSigchain(context.TODO(), sc, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusStatementInvalid, result.Status)
	require.Equal(t, result.Err, "failed to user verify: name mismatch alice != alice2")
}

func TestResultGithubWrongService(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Clock(clock))
	sc := keys.NewSigchain(sk.ID())

	invalid := &user.User{KID: sk.ID(), Service: "github2", Name: "gabriel"}
	msg, err := invalid.Sign(sk)
	require.NoError(t, err)

	usrs.Client().SetProxy("", func(ctx context.Context, req *http.Request, headers []http.Header) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(githubMock("alice", "1", msg))}
	})

	usr, err := user.New(sk.ID(), "github", "alice", "https://gist.github.com/alice/1", 1)
	require.NoError(t, err)
	b, err := json.Marshal(usr)
	require.NoError(t, err)
	st, err := keys.NewSigchainStatement(sc, b, sk, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	result, err := usrs.CheckSigchain(context.TODO(), sc, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusStatementInvalid, result.Status)
	require.Equal(t, result.Err, "failed to user verify: service mismatch github != github2")
}
