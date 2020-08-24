package user_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
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

func TestResultTwitter(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	// usr, err := user.NewForSigning(sk.ID(), "twitter", "bob")
	// require.NoError(t, err)
	// msg, err := usr.Sign(sk)
	// require.NoError(t, err)
	// t.Logf(msg)

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "twitter", "bob", "https://twitter.com/bob/status/1205589994380783616", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	// Set error response
	req.SetError("https://mobile.twitter.com/bob/status/1205589994380783616", errors.Errorf("testing"))
	require.NoError(t, err)

	result, err := users.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, user.StatusConnFailure, result.Status)
	require.Equal(t, "testing", result.Err)
	require.Equal(t, "twitter", result.User.Service)
	require.Equal(t, "bob", result.User.Name)
	require.Equal(t, int64(0), result.VerifiedAt)
	require.Equal(t, int64(1234567890002), result.Timestamp)

	_, err = user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	// Set valid response
	req.SetResponse("https://mobile.twitter.com/bob/status/1205589994380783616", testdata(t, "testdata/twitter/1205589994380783616"))

	result, err = users.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "twitter", result.User.Service)
	require.Equal(t, "bob", result.User.Name)
	require.Equal(t, int64(1234567890004), result.VerifiedAt)
	require.Equal(t, int64(1234567890004), result.Timestamp)

	// Set error response again
	req.SetError("https://mobile.twitter.com/bob/status/1205589994380783616", errors.Errorf("testing2"))
	require.NoError(t, err)

	result, err = users.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, user.StatusConnFailure, result.Status)
	require.Equal(t, "testing2", result.Err)
	require.Equal(t, "twitter", result.User.Service)
	require.Equal(t, "bob", result.User.Name)
	require.Equal(t, int64(1234567890004), result.VerifiedAt)
	require.Equal(t, int64(1234567890005), result.Timestamp)

	result, err = users.Get(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "twitter", result.User.Service)
	require.Equal(t, "bob", result.User.Name)

	result, err = users.User(context.TODO(), "bob@twitter")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "twitter", result.User.Service)
	require.Equal(t, "bob", result.User.Name)

	kids, err := users.KIDs(context.TODO())
	require.NoError(t, err)
	require.Equal(t, 1, len(kids))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), kids[0])

	res, err := users.Search(context.TODO(), &user.SearchRequest{Query: "bob"})
	require.NoError(t, err)
	require.Equal(t, 1, len(res))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), res[0].KID)
}

func TestResultTwitterInvalidStatement(t *testing.T) {
	// Same as TestResultTwitter but 0x02 seed instead of 0x01
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "twitter", "bob", "https://twitter.com/bob/status/1205589994380783616", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	req.SetResponse("https://mobile.twitter.com/bob/status/1205589994380783616", testdata(t, "testdata/twitter/1205589994380783616"))

	result, err := users.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, user.StatusStatementInvalid, result.Status)
	require.Equal(t, "failed to user verify: verify failed", result.Err)
	require.Equal(t, "twitter", result.User.Service)
	require.Equal(t, "bob", result.User.Name)
	require.Equal(t, int64(0), result.VerifiedAt)
	require.Equal(t, int64(1234567890002), result.Timestamp)
}
