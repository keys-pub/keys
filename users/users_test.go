package users_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/users"
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

func TestCheckNoUsers(t *testing.T) {
	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc := keys.NewSigchain(sk.ID())

	client := http.NewMock()
	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Client(client), users.Clock(clock))

	result, err := usrs.CheckSigchain(context.TODO(), sc)
	require.NoError(t, err)
	require.Nil(t, result)

	rk := keys.GenerateEdX25519Key()
	result, err = usrs.Update(context.TODO(), rk.ID())
	require.NoError(t, err)
	require.Nil(t, result)
}

func TestCheckFailure(t *testing.T) {
	client := http.NewMock()
	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Client(client), users.Clock(clock))

	msg := "BEGIN MESSAGE.HWNhu0mATP1TJvQ 2MsM6UREvrdpmJL mlr4taMzxi0olt7 nV35Vkco9gjJ3wyZ0z9hiq2OxrlFUT QVAdNgSZPX3TCKq 6Xr2MZHgg6PbuKB KKAcQRbMCMprx0eQ9AAmF37oSytfuD ekFhesy6sjWc4kJ XA4C6PAxTFwtO14 CEXTYQyBxGH2CYAsm4w2O9xq9TNTZw lo0e7ydqx99UXE8 Qivwr0VNs5.END MESSAGE."
	client.SetResponse("https://mobile.twitter.com/boboloblaw/status/1259188857846632448", []byte(msg))

	usr := &user.User{
		Name:    "gabriel",
		KID:     keys.ID("kex1d69g7mzjjn8cfm3ssdr9u8z8mh2d35cvjzsrwrndt4d006uhh69qyx2k5x"),
		Seq:     1,
		Service: "twitter",
		URL:     "https://twitter.com/boboloblaw/status/1259188857846632448",
	}
	result := usrs.RequestVerify(context.TODO(), usr)
	require.Equal(t, usr.Name, result.User.Name)
	require.Equal(t, result.Status, user.StatusFailure)
	require.Equal(t, result.Err, "path invalid (name mismatch) for url https://twitter.com/boboloblaw/status/1259188857846632448")
}

func TestSigchainUsersUpdate(t *testing.T) {
	// users.SetLogger(users.NewLogger(users.DebugLevel))
	// user.SetLogger(users.NewLogger(users.DebugLevel))
	// link.SetLogger(users.NewLogger(users.DebugLevel))

	kid := keys.ID("kex1e26rq9vrhjzyxhep0c5ly6rudq7m2cexjlkgknl2z4lqf8ga3uasz3s48m")
	sc := keys.NewSigchain(kid)

	b := testdata(t, "testdata/twitter/statement.json")
	var st keys.Statement
	err := json.Unmarshal(b, &st)
	require.NoError(t, err)

	err = sc.Add(&st)
	require.NoError(t, err)

	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	client := http.NewMock()
	usrs := users.New(ds, scs, users.Client(client), users.Clock(clock))

	msg := testdata(t, "testdata/twitter/1222706272849391616.json")
	require.NoError(t, err)
	client.SetResponse("https://api.twitter.com/2/tweets/1222706272849391616?expansions=author_id", []byte(msg))

	err = scs.Save(sc)
	require.NoError(t, err)

	result, err := usrs.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
}

func TestSigchainRevokeUpdate(t *testing.T) {
	// user.SetLogger(user.NewLogger(user.DebugLevel))
	clock := tsutil.NewTestClock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	client := http.NewMock()
	usrs := users.New(ds, scs, users.Client(client), users.Clock(clock))

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

	client.SetResponse("https://api.twitter.com/2/tweets/1?expansions=author_id", []byte(twitterMock("gabriel", "1", msg)))

	err = scs.Save(sc)
	require.NoError(t, err)

	result, err := usrs.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, result.Status)

	// Revoke
	_, err = sc.Revoke(1, sk)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)
	// Don't update here to test revoke + new statement updates correctly

	// Update #2
	stu2, err := user.New(kid, "twitter", "gabriel", "https://mobile.twitter.com/gabriel/status/2", 3)
	require.NoError(t, err)
	st2, err := user.NewSigchainStatement(sc, stu2, sk, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	client.SetResponse("https://api.twitter.com/2/tweets/2?expansions=author_id", []byte(twitterMock("gabriel", "2", msg)))

	err = scs.Save(sc)
	require.NoError(t, err)

	result, err = usrs.Update(context.TODO(), kid)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, user.StatusOK, result.Status)
}

func TestCheckForExisting(t *testing.T) {
	var err error

	clock := tsutil.NewTestClock()
	client := http.NewMock()
	ds := dstore.NewMem()
	scs := keys.NewSigchains(ds)
	usrs := users.New(ds, scs, users.Client(client), users.Clock(clock))

	sk1 := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc1 := keys.NewSigchain(sk1.ID())
	_, err = user.MockStatement(sk1, sc1, "alice", "echo", client, clock)
	require.NoError(t, err)
	kid, err := usrs.CheckForExisting(context.TODO(), sc1)
	require.NoError(t, err)
	require.Empty(t, kid)
	err = scs.Save(sc1)
	require.NoError(t, err)
	_, err = usrs.Update(context.TODO(), sk1.ID())
	require.NoError(t, err)

	sk2 := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	sc2 := keys.NewSigchain(sk2.ID())
	_, err = user.MockStatement(sk2, sc2, "alice", "echo", client, clock)
	require.NoError(t, err)
	kid, err = usrs.CheckForExisting(context.TODO(), sc2)
	require.NoError(t, err)
	require.Equal(t, kid, sk1.ID())

}
