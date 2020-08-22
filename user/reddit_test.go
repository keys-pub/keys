package user_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/stretchr/testify/require"
)

func TestResultReddit(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	users := user.NewUsers(ds, scs, req, clock)

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
	err = scs.Save(sc)
	require.NoError(t, err)

	_, err = user.NewSigchainStatement(sc, stu, sk, clock.Now())
	require.EqualError(t, err, "user set in sigchain already")

	req.SetResponse("https://www.reddit.com/r/keyspubmsgs/comments/f8g9vd/charlie.json", testdata(t, "testdata/reddit/charlie.json"))

	result, err := users.Update(context.TODO(), sk.ID())
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	require.Equal(t, user.StatusOK, result.Status)
	require.Equal(t, "reddit", result.User.Service)
	require.Equal(t, "charlie", result.User.Name)
	require.Equal(t, int64(1234567890003), result.VerifiedAt)
	require.Equal(t, int64(1234567890003), result.Timestamp)
}
