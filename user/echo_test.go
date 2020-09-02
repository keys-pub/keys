package user_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/link"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/stretchr/testify/require"
)

func TestResultEcho(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	usr, err := user.NewForSigning(sk.ID(), "echo", "alice")
	require.NoError(t, err)
	msg, err := usr.Sign(sk)
	require.NoError(t, err)
	err = user.Verify(msg, usr)
	require.NoError(t, err)

	urs := "test://echo/alice/" + sk.ID().String() + "/" + url.QueryEscape(strings.ReplaceAll(msg, "\n", " "))
	expected := `test://echo/alice/kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077/BEGIN+MESSAGE.+c0ypzQnuMjHRspp+4e0pl3TYCllN7ZG+MfKStJEnWVz5Uxt+lHFJtaTmEjPdy43+aOvtlDN9ZKwtQqS+WzHAKQB7RxKTCKq+6Xr2MZHgg4UNRDb+Zy2loGoGN3Mvxd4+r7FIwpZOJPE1JEq+D2gGjkgLByR9CFG+2aCgRgZZwl5UAa4+6bmBzjE1RqUnMN5+RDaVlacMSHyIP0d+IbCHwBmy0ZnY9pb+T0X.+END+MESSAGE.`
	require.Equal(t, expected, urs)

	sc := keys.NewSigchain(sk.ID())
	stu, err := user.New(sk.ID(), "echo", "alice", urs, sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	result, err := users.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	t.Logf("Result: %+v", result)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "echo", result.User.Service)
	require.Equal(t, "alice", result.User.Name)
	require.Equal(t, int64(1234567890002), result.VerifiedAt)
	require.Equal(t, int64(1234567890002), result.Timestamp)

	result, err = users.Get(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "echo", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	result, err = users.User(context.TODO(), "alice@echo")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "echo", result.User.Service)
	require.Equal(t, "alice", result.User.Name)

	kids, err := users.KIDs(context.TODO())
	require.NoError(t, err)
	require.Equal(t, 1, len(kids))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), kids[0])

	// Echo is hidden from search
	res, err := users.Search(context.TODO(), &user.SearchRequest{Query: "alice@echo"})
	require.NoError(t, err)
	require.Equal(t, 0, len(res))
	// require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), res[0].KID)
}

func TestRequestVerifyEcho(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, user.Requestor(req), user.Clock(clock))

	usrSign, err := user.NewForSigning(sk.ID(), "echo", "alice")
	require.NoError(t, err)
	msg, err := usrSign.Sign(sk)
	require.NoError(t, err)
	msg = url.QueryEscape(strings.ReplaceAll(msg, "\n", " "))

	urs := "test://echo/alice/" + sk.ID().String() + "/" + msg

	norm, err := link.Echo.NormalizeURLString("alice", urs)
	require.NoError(t, err)

	usr := &user.User{
		KID:     sk.ID(),
		Name:    "alice",
		Service: "echo",
		URL:     norm,
	}

	result := users.RequestVerify(context.TODO(), usr)
	t.Logf("result: %+v", result)
	require.Equal(t, user.StatusOK, result.Status)
}
