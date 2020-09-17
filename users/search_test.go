package users_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/users"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestSearchUsers(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))

	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	ds.SetClock(clock)
	scs := keys.NewSigchains(ds)
	scs.SetClock(clock)

	req := request.NewMockRequestor()
	usrs := users.New(ds, scs, users.Requestor(req), users.Clock(clock))
	ctx := context.TODO()

	results, err := usrs.Search(ctx, &users.SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	require.NoError(t, err)

	// Add alice@github
	testSaveUser(t, usrs, scs, alice, "alice", "github", clock, req)

	for i := 10; i < 15; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("name%d", i)
		testSaveUser(t, usrs, scs, key, name, "github", clock, req)
		_, err = usrs.Update(ctx, key.ID())
		require.NoError(t, err)
	}

	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	// Search "alic"
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, alice.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "github", results[0].Result.User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Result.User.URL)
	require.Equal(t, 1, results[0].Result.User.Seq)
	require.Equal(t, int64(1234567890044), results[0].Result.VerifiedAt)
	require.Equal(t, int64(1234567890044), results[0].Result.Timestamp)

	// Search "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, alice.ID(), results[0].Result.User.KID)

	// Search "kbx1rvd43h2sag2tvrdp0duse5p82nvhpjd6hpjwhv7q7vqklega8atshec5ws"
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "kbx1rvd43h2sag2tvrdp0duse5p82nvhpjd6hpjwhv7q7vqklega8atshec5ws"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, alice.ID(), results[0].Result.User.KID)

	// Search kid not found
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "kex1akxmcdxr84zk3lpexrzjznelyje4dnnq7tca25m4j6eg7dd746eq057ma9"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Revoke alice, update
	sc, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)
	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Add alicenew@github
	aliceNewSt := testSaveUser(t, usrs, scs, alice, "alicenew", "github", clock, req)
	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	// Search "al", match "alicenew".
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, "alicenew", results[0].Result.User.Name)
	require.Equal(t, "github", results[0].Result.User.Service)
	require.Equal(t, "https://gist.github.com/alicenew/1", results[0].Result.User.URL)
	require.Equal(t, 3, results[0].Result.User.Seq)

	// Add alice@twitter
	alice2 := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x03}, 32)))
	testSaveUser(t, usrs, scs, alice2, "alice", "twitter", clock, req)
	_, err = usrs.Update(ctx, alice2.ID())
	require.NoError(t, err)

	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, alice2.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "twitter", results[0].Result.User.Service)
	require.Equal(t, 1, results[0].Result.User.Seq)
	require.NotNil(t, results[1].Result)
	require.Equal(t, alice.ID(), results[1].Result.User.KID)
	require.Equal(t, "alicenew", results[1].Result.User.Name)
	require.Equal(t, "github", results[1].Result.User.Service)
	require.Equal(t, 3, results[1].Result.User.Seq)

	// Revoke alicenew@github
	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)
	_, err = sc.Revoke(aliceNewSt.Seq, alice)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)
	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "twitter", results[0].Result.User.Service)

	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alice@twitter"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "twitter", results[0].Result.User.Service)

	// Check Documents
	iter, err := ds.DocumentIterator(context.TODO(), "kid")
	require.NoError(t, err)
	spew, err := docs.Spew(iter)
	require.NoError(t, err)
	require.Equal(t, string(testdata(t, "testdata/kid.spew")), spew.String())

	iter, err = ds.DocumentIterator(context.TODO(), "user")
	require.NoError(t, err)
	spew, err = docs.Spew(iter)
	require.NoError(t, err)
	require.Equal(t, string(testdata(t, "testdata/user.spew")), spew.String())
}

func TestFind(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	var err error
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	ds.SetClock(clock)
	scs := keys.NewSigchains(ds)
	scs.SetClock(clock)

	req := request.NewMockRequestor()
	usrs := users.New(ds, scs, users.Requestor(req), users.Clock(clock))
	ctx := context.TODO()

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	require.NoError(t, err)

	// Add alice@github
	testSaveUser(t, usrs, scs, alice, "alice", "github", clock, req)

	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	// Find "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"
	res, err := usrs.Find(ctx, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"))
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, alice.ID(), res.User.KID)

	// Find "kbx1rvd43h2sag2tvrdp0duse5p82nvhpjd6hpjwhv7q7vqklega8atshec5ws"
	res, err = usrs.Find(ctx, keys.ID("kbx1rvd43h2sag2tvrdp0duse5p82nvhpjd6hpjwhv7q7vqklega8atshec5ws"))
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, alice.ID(), res.User.KID)

	// Find (not found)
	rand := keys.GenerateEdX25519Key()
	res, err = usrs.Find(ctx, rand.ID())
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestUsersEmpty(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	ds.SetClock(clock)
	scs := keys.NewSigchains(ds)
	scs.SetClock(clock)

	req := request.NewMockRequestor()
	users := users.New(ds, scs, users.Requestor(req), users.Clock(clock))

	key := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	// Test empty
	ctx := context.TODO()
	result, err := users.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, result)

	res, err := users.Get(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestUserValidateName(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	ds.SetClock(clock)
	scs := keys.NewSigchains(ds)
	scs.SetClock(clock)

	req := request.NewMockRequestor()
	usrs := users.New(ds, scs, users.Requestor(req), users.Clock(clock))

	key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x20}, 32)))

	// Test MixedCase
	_, err := saveUser(usrs, scs, key, "MixedCase", "github", clock, req)
	require.EqualError(t, err, "name has an invalid character")
	_, err = saveUser(usrs, scs, key, "MixedCase", "twitter", clock, req)
	require.EqualError(t, err, "name has an invalid character")
	_, err = saveUser(usrs, scs, key, "MixedCase", "reddit", clock, req)
	require.EqualError(t, err, "name has an invalid character")

	// Long length
	_, err = saveUser(usrs, scs, key, "reallylongusernamereallylongusernamereallylongusername", "github", clock, req)
	require.EqualError(t, err, "github name is too long, it must be less than 40 characters")
	_, err = saveUser(usrs, scs, key, "reallylongusernamereallylongusernamereallylongusername", "twitter", clock, req)
	require.EqualError(t, err, "twitter name is too long, it must be less than 16 characters")
	_, err = saveUser(usrs, scs, key, "reallylongusernamereallylongusernamereallylongusername", "reddit", clock, req)
	require.EqualError(t, err, "reddit name is too long, it must be less than 21 characters")
}

func TestUserValidateUpdateInvalid(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	ds.SetClock(clock)
	scs := keys.NewSigchains(ds)
	scs.SetClock(clock)

	req := request.NewMockRequestor()
	users := users.New(ds, scs, users.Requestor(req), users.Clock(clock))

	// Unvalidated user to sigchain
	key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x021}, 32)))
	testingURL := "https://reddit.com/r/keyspubmsgs/comments/123/Testing"
	usr := &user.User{
		KID:     key.ID(),
		Service: "reddit",
		Name:    "Testing",
		URL:     testingURL,
		Seq:     1,
	}
	smsg, err := usr.Sign(key)
	require.NoError(t, err)
	msg := mockRedditMessage("Testing", smsg, "keyspubmsgs")
	req.SetResponse(mockRedditURL(testingURL), []byte(msg))

	sc := keys.NewSigchain(key.ID())

	_, err = user.NewSigchainStatement(sc, usr, key, clock.Now())
	require.EqualError(t, err, "name has an invalid character")

	// Go around validate check and add
	b, err := usr.MarshalJSON()
	require.NoError(t, err)
	st, err := keys.NewSigchainStatement(sc, b, key, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	ctx := context.TODO()
	result, err := users.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, result)

	res, err := users.Get(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestReddit(t *testing.T) {
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	ds.SetClock(clock)
	scs := keys.NewSigchains(ds)
	scs.SetClock(clock)

	req := request.NewMockRequestor()
	usrs := users.New(ds, scs, users.Requestor(req), users.Clock(clock))

	key := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	redditURL := "https://reddit.com/r/keyspubmsgs/comments/123/alice"
	usr := &user.User{
		KID:     key.ID(),
		Service: "reddit",
		Name:    "alice",
		URL:     redditURL,
		Seq:     1,
	}
	sc := keys.NewSigchain(key.ID())
	st, err := user.NewSigchainStatement(sc, usr, key, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.Save(sc)
	require.NoError(t, err)

	ctx := context.TODO()

	smsg, err := usr.Sign(key)
	require.NoError(t, err)
	msg := mockRedditMessage("alice", smsg, "keyspubmsgs")
	req.SetResponse(mockRedditURL("alice"), []byte(msg))

	result, err := usrs.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, result.Status)

	// Different name
	msg = mockRedditMessage("alice2", smsg, "keyspubmsgs")
	req.SetResponse(mockRedditURL("alice"), []byte(msg))
	result, err = usrs.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, user.StatusContentInvalid, result.Status)

	// Different subreddit
	msg = mockRedditMessage("alice", smsg, "keyspubmsgs2")
	req.SetResponse(mockRedditURL("alice"), []byte(msg))
	result, err = usrs.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, user.StatusContentInvalid, result.Status)
}

func TestSearchUsersRequestErrors(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))

	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	ds.SetClock(clock)
	scs := keys.NewSigchains(ds)
	scs.SetClock(clock)

	req := request.NewMockRequestor()
	usrs := users.New(ds, scs, users.Requestor(req), users.Clock(clock))
	ctx := context.TODO()

	results, err := usrs.Search(ctx, &users.SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	// Add alice@github
	testSaveUser(t, usrs, scs, alice, "alice", "github", clock, req)

	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, alice.ID(), results[0].KID)
	require.Equal(t, int64(1234567890004), results[0].Result.Timestamp)
	require.Equal(t, int64(1234567890004), results[0].Result.VerifiedAt)

	data, err := req.Response("https://gist.github.com/alice/1")
	require.NoError(t, err)

	// Set 500 error for alice@github
	req.SetError("https://gist.github.com/alice/1", request.ErrHTTP{StatusCode: 500})
	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	// Search still includes (connection failure)
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), results[0].Result.User.KID)
	require.Equal(t, user.StatusConnFailure, results[0].Result.Status)
	require.Equal(t, int64(1234567890009), results[0].Result.Timestamp)
	require.Equal(t, int64(1234567890004), results[0].Result.VerifiedAt)

	// If connection failure persists, should remove from search
	clock.Add(time.Hour * 24 * 3)
	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// List by status
	fail, err := usrs.Status(ctx, user.StatusConnFailure)
	require.NoError(t, err)
	require.Equal(t, 1, len(fail))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), fail[0])

	// Set 404 error for alice@github
	req.SetError("https://gist.github.com/alice/1", request.ErrHTTP{StatusCode: 404})
	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Check Documents
	iter, err := ds.DocumentIterator(context.TODO(), "kid")
	require.NoError(t, err)
	spew, err := docs.Spew(iter)
	require.NoError(t, err)
	require.Equal(t, string(testdata(t, "testdata/kid2.spew")), spew.String())

	iter, err = ds.DocumentIterator(context.TODO(), "user")
	require.NoError(t, err)
	spew, err = docs.Spew(iter)
	require.NoError(t, err)
	require.Equal(t, "", spew.String())

	// Unset error
	req.SetResponse("https://gist.github.com/alice/1", data)
	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = usrs.Search(ctx, &users.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID().String(), results[0].KID.String())
}

func TestExpired(t *testing.T) {
	var err error
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)

	clock := tsutil.NewTestClock()
	req := request.NewMockRequestor()
	usrs := users.New(ds, scs, users.Requestor(req), users.Clock(clock))
	ctx := context.TODO()

	ids, err := usrs.Expired(ctx, time.Hour, time.Hour*24*60)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	// Add alice@github
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	testSaveUser(t, usrs, scs, alice, "alice", "github", clock, req)

	_, err = usrs.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err := usrs.Search(ctx, &users.SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "github", results[0].Result.User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Result.User.URL)
	require.Equal(t, 1, results[0].Result.User.Seq)
	require.Equal(t, int64(1234567890002), results[0].Result.VerifiedAt)
	require.Equal(t, int64(1234567890002), results[0].Result.Timestamp)

	ids, err = usrs.Expired(ctx, time.Hour, time.Hour*24*60)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	// Test expired
	clock.Add(time.Hour * 2)

	ids, err = usrs.Expired(ctx, time.Hour, time.Hour*24*60)
	require.NoError(t, err)
	require.Equal(t, 1, len(ids))
	require.Equal(t, []keys.ID{alice.ID()}, ids)

	// Test max age
	clock.Add(time.Hour * 24 * 30)

	ids, err = usrs.Expired(ctx, time.Hour, time.Hour*24*7)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))
}

func testSaveUser(t *testing.T, users *users.Users, scs *keys.Sigchains, key *keys.EdX25519Key, name string, service string, clock tsutil.Clock, mock *request.MockRequestor) *keys.Statement {
	st, err := saveUser(users, scs, key, name, service, clock, mock)
	require.NoError(t, err)
	return st
}

func saveUser(users *users.Users, scs *keys.Sigchains, key *keys.EdX25519Key, name string, service string, clock tsutil.Clock, mock *request.MockRequestor) (*keys.Statement, error) {
	url := ""
	murl := ""
	switch service {
	case "github":
		url = fmt.Sprintf("https://gist.github.com/%s/1", name)
		murl = url
	case "twitter":
		url = fmt.Sprintf("https://twitter.com/%s/status/1", name)
		murl = fmt.Sprintf("https://mobile.twitter.com/%s/status/1", name)
	case "reddit":
		url = fmt.Sprintf("https://reddit.com/r/keyspubmsgs/comments/%s", name)
		murl = url
	default:
		return nil, errors.Errorf("unsupported service in test")
	}

	sc, err := scs.Sigchain(key.ID())
	if err != nil {
		return nil, err
	}
	if sc == nil {
		sc = keys.NewSigchain(key.ID())
	}

	usr, err := user.New(key.ID(), service, name, url, sc.LastSeq()+1)
	if err != nil {
		return nil, err
	}

	st, err := user.NewSigchainStatement(sc, usr, key, clock.Now())
	if err != nil {
		return nil, err
	}
	if err = sc.Add(st); err != nil {
		return nil, err
	}

	if err = scs.Save(sc); err != nil {
		return nil, err
	}

	msg, err := usr.Sign(key)
	if err != nil {
		return nil, err
	}
	mock.SetResponse(murl, []byte(msg))

	return st, nil
}

func TestNewSigchainUserStatement(t *testing.T) {
	clock := tsutil.NewTestClock()
	key := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc := keys.NewSigchain(key.ID())
	usr, err := user.New(key.ID(), "github", "alice", "https://gist.github.com/alice/1", 1)
	require.NoError(t, err)
	st, err := user.NewSigchainStatement(sc, usr, key, clock.Now())
	require.NoError(t, err)
	require.Equal(t, st.Seq, usr.Seq)

	usr, err = user.New(key.ID(), "github", "alice", "https://gist.github.com/alice/1", 100)
	require.NoError(t, err)
	_, err = user.NewSigchainStatement(sc, usr, key, clock.Now())
	require.EqualError(t, err, "user seq mismatch")
}

func TestSearch(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	clock := tsutil.NewTestClock()
	ds := docs.NewMem()
	scs := keys.NewSigchains(ds)
	req := request.NewMockRequestor()
	usrs := users.New(ds, scs, users.Requestor(req), users.Clock(clock))
	ctx := context.TODO()

	for i := 0; i < 10; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("a%d", i)
		testSaveUser(t, usrs, scs, key, name, "github", clock, req)
		_, err := usrs.Update(ctx, key.ID())
		require.NoError(t, err)
	}
	for i := 10; i < 20; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("b%d", i)
		testSaveUser(t, usrs, scs, key, name, "github", clock, req)
		_, err := usrs.Update(ctx, key.ID())
		require.NoError(t, err)
	}

	results, err := usrs.Search(ctx, &users.SearchRequest{Query: "a"})
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, "kex18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5s0v3alm", results[0].KID.String())
	require.NotNil(t, 1, results[0].Result)
	require.Equal(t, "a0", results[0].Result.User.Name)

	results, err = usrs.Search(ctx, &users.SearchRequest{Limit: 1000})
	require.NoError(t, err)
	require.Equal(t, 20, len(results))
	require.Equal(t, "kex18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5s0v3alm", results[0].KID.String())
}

func mockRedditMessage(author string, msg string, subreddit string) string {
	msg = strings.ReplaceAll(msg, "\n", " ")
	return `[{   
		"kind": "Listing",
		"data": {
			"children": [
				{
					"kind": "t3",
					"data": {
						"author": "` + author + `",
						"selftext": "` + msg + `",
						"subreddit": "` + subreddit + `"
					}
				}
			]
		}
    }]`
}

func mockRedditURL(name string) string {
	return "https://www.reddit.com/r/keyspubmsgs/comments/123/" + name + ".json"
}
