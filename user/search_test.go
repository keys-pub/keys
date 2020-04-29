package user_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/ds"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/util"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestSearchUsers(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := ds.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	results, err := ust.Search(ctx, &user.SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	// Add alice@github
	testSaveUser(t, ust, scs, alice, "alice", "github", clock, req)

	for i := 10; i < 15; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("name%d", i)
		testSaveUser(t, ust, scs, key, name, "github", clock, req)
		_, err = ust.Update(ctx, key.ID())
		require.NoError(t, err)
	}

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, alice.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "github", results[0].Result.User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Result.User.URL)
	require.Equal(t, 1, results[0].Result.User.Seq)
	require.Equal(t, int64(1234567890034), results[0].Result.VerifiedAt)
	require.Equal(t, int64(1234567890033), results[0].Result.Timestamp)

	// Revoke alice, update
	sc, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &user.SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Add alicenew@github
	aliceNewSt := testSaveUser(t, ust, scs, alice, "alicenew", "github", clock, req)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	// Search "al", match "alicenew".
	results, err = ust.Search(ctx, &user.SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, "alicenew", results[0].Result.User.Name)
	require.Equal(t, "github", results[0].Result.User.Service)
	require.Equal(t, "https://gist.github.com/alicenew/1", results[0].Result.User.URL)
	require.Equal(t, 3, results[0].Result.User.Seq)

	// Add alice@twitter
	alice2 := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x03}, 32)))
	testSaveUser(t, ust, scs, alice2, "alice", "twitter", clock, req)
	_, err = ust.Update(ctx, alice2.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alic"})
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
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "twitter", results[0].Result.User.Service)

	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alice@twitter"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "twitter", results[0].Result.User.Service)

	// Check Documents
	iter, err := dst.Documents(context.TODO(), "kid", nil)
	require.NoError(t, err)
	spew, err := ds.Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, testdataString(t, "testdata/kid.spew"), spew.String())

	iter, err = dst.Documents(context.TODO(), "user", nil)
	require.NoError(t, err)
	spew, err = ds.Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, testdataString(t, "testdata/user.spew"), spew.String())
}

func TestUserStoreEmpty(t *testing.T) {
	clock := newClock()
	dst := ds.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)

	key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	// Test empty
	ctx := context.TODO()
	result, err := ust.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, result)

	res, err := ust.Get(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestUserValidateName(t *testing.T) {
	clock := newClock()
	dst := ds.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)

	key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x20}, 32)))

	// Test MixedCase
	_, err := saveUser(ust, scs, key, "MixedCase", "github", clock, req)
	require.EqualError(t, err, "user name should be lowercase")
	_, err = saveUser(ust, scs, key, "MixedCase", "twitter", clock, req)
	require.EqualError(t, err, "user name should be lowercase")
	_, err = saveUser(ust, scs, key, "MixedCase", "reddit", clock, req)
	require.EqualError(t, err, "user name should be lowercase")

	// Long length
	_, err = saveUser(ust, scs, key, "reallylongusernamereallylongusernamereallylongusername", "github", clock, req)
	require.EqualError(t, err, "github name too long")
	_, err = saveUser(ust, scs, key, "reallylongusernamereallylongusernamereallylongusername", "twitter", clock, req)
	require.EqualError(t, err, "twitter name too long")
	_, err = saveUser(ust, scs, key, "reallylongusernamereallylongusernamereallylongusername", "reddit", clock, req)
	require.EqualError(t, err, "reddit name too long")
}

func TestUserValidateUpdateInvalid(t *testing.T) {
	clock := newClock()
	dst := ds.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)

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

	_, err = user.NewUserSigchainStatement(sc, usr, key, clock.Now())
	require.EqualError(t, err, "user name should be lowercase")

	// Go around validate check and add
	b, err := usr.MarshalJSON()
	require.NoError(t, err)
	st, err := keys.NewSigchainStatement(sc, b, key, "user", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	ctx := context.TODO()
	result, err := ust.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, result)

	res, err := ust.Get(ctx, key.ID())
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestReddit(t *testing.T) {
	clock := newClock()
	dst := ds.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)

	key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	redditURL := "https://reddit.com/r/keyspubmsgs/comments/123/alice"
	usr := &user.User{
		KID:     key.ID(),
		Service: "reddit",
		Name:    "alice",
		URL:     redditURL,
		Seq:     1,
	}
	sc := keys.NewSigchain(key.ID())
	st, err := user.NewUserSigchainStatement(sc, usr, key, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	ctx := context.TODO()

	smsg, err := usr.Sign(key)
	require.NoError(t, err)
	msg := mockRedditMessage("alice", smsg, "keyspubmsgs")
	req.SetResponse(mockRedditURL(redditURL), []byte(msg))

	result, err := ust.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, user.StatusOK, result.Status)

	// Different name
	msg = mockRedditMessage("alice2", smsg, "keyspubmsgs")
	req.SetResponse(mockRedditURL(redditURL), []byte(msg))
	result, err = ust.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, user.StatusContentInvalid, result.Status)

	// Different subreddit
	msg = mockRedditMessage("alice", smsg, "keyspubmsgs2")
	req.SetResponse(mockRedditURL(redditURL), []byte(msg))
	result, err = ust.Update(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, user.StatusContentInvalid, result.Status)
}

func TestSearchUsersRequestErrors(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := ds.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	results, err := ust.Search(ctx, &user.SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	// Add alice@github
	testSaveUser(t, ust, scs, alice, "alice", "github", clock, req)

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, alice.ID(), results[0].KID)
	require.Equal(t, int64(1234567890003), results[0].Result.Timestamp)
	require.Equal(t, int64(1234567890004), results[0].Result.VerifiedAt)

	data, err := req.Response("https://gist.github.com/alice/1")
	require.NoError(t, err)

	// Set 500 error for alice@github
	req.SetError("https://gist.github.com/alice/1", util.ErrHTTP{StatusCode: 500})
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].Result)
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), results[0].Result.User.KID)
	require.Equal(t, user.StatusConnFailure, results[0].Result.Status)
	require.Equal(t, int64(1234567890007), results[0].Result.Timestamp)
	require.Equal(t, int64(1234567890004), results[0].Result.VerifiedAt)

	// List by status
	fail, err := ust.Status(ctx, user.StatusConnFailure)
	require.NoError(t, err)
	require.Equal(t, 1, len(fail))
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), fail[0])

	// Set 404 error for alice@github
	req.SetError("https://gist.github.com/alice/1", util.ErrHTTP{StatusCode: 404})
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Check Documents
	iter, err := dst.Documents(context.TODO(), "kid", nil)
	require.NoError(t, err)
	spew, err := ds.Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, testdataString(t, "testdata/kid2.spew"), spew.String())

	iter, err = dst.Documents(context.TODO(), "user", nil)
	require.NoError(t, err)
	spew, err = ds.Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, "", spew.String())

	// Unset error
	req.SetResponse("https://gist.github.com/alice/1", data)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &user.SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID().String(), results[0].KID.String())
}

func TestExpired(t *testing.T) {
	dst := ds.NewMem()
	scs := keys.NewSigchainStore(dst)

	clock := newClock()
	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	ids, err := ust.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	ids, err = ust.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	// Add alice@github
	testSaveUser(t, ust, scs, alice, "alice", "github", clock, req)

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err := ust.Search(ctx, &user.SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID(), results[0].Result.User.KID)
	require.Equal(t, "alice", results[0].Result.User.Name)
	require.Equal(t, "github", results[0].Result.User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Result.User.URL)
	require.Equal(t, 1, results[0].Result.User.Seq)
	require.Equal(t, int64(1234567890003), results[0].Result.VerifiedAt)
	require.Equal(t, int64(1234567890002), results[0].Result.Timestamp)

	ids, err = ust.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	ids, err = ust.Expired(ctx, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, []keys.ID{alice.ID()}, ids)
}

func testSaveUser(t *testing.T, ust *user.Store, scs keys.SigchainStore, key *keys.EdX25519Key, name string, service string, clock *clock, mock *util.MockRequestor) *keys.Statement {
	st, err := saveUser(ust, scs, key, name, service, clock, mock)
	require.NoError(t, err)
	return st
}

func saveUser(ust *user.Store, scs keys.SigchainStore, key *keys.EdX25519Key, name string, service string, clock *clock, mock *util.MockRequestor) (*keys.Statement, error) {
	url := ""
	switch service {
	case "github":
		url = fmt.Sprintf("https://gist.github.com/%s/1", name)
	case "twitter":
		url = fmt.Sprintf("https://twitter.com/%s/status/1", name)
	case "reddit":
		url = fmt.Sprintf("https://reddit.com/r/keyspubmsgs/comments/%s", name)
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

	usr, err := user.NewUser(ust, key.ID(), service, name, url, sc.LastSeq()+1)
	if err != nil {
		return nil, err
	}

	st, err := user.NewUserSigchainStatement(sc, usr, key, clock.Now())
	if err != nil {
		return nil, err
	}
	if err = sc.Add(st); err != nil {
		return nil, err
	}

	if err = scs.SaveSigchain(sc); err != nil {
		return nil, err
	}

	msg, err := usr.Sign(key)
	if err != nil {
		return nil, err
	}
	mock.SetResponse(url, []byte(msg))

	return st, nil
}

func TestNewSigchainUserStatement(t *testing.T) {
	clock := newClock()
	dst := ds.NewMem()
	scs := keys.NewSigchainStore(dst)
	key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)
	sc := keys.NewSigchain(key.ID())
	usr, err := user.NewUser(ust, key.ID(), "github", "alice", "https://gist.github.com/alice/1", 1)
	require.NoError(t, err)
	st, err := user.NewUserSigchainStatement(sc, usr, key, clock.Now())
	require.NoError(t, err)
	require.Equal(t, st.Seq, usr.Seq)

	usr, err = user.NewUser(ust, key.ID(), "github", "alice", "https://gist.github.com/alice/1", 100)
	require.NoError(t, err)
	_, err = user.NewUserSigchainStatement(sc, usr, key, clock.Now())
	require.EqualError(t, err, "user seq mismatch")
}

func TestSearch(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	clock := newClock()
	dst := ds.NewMem()
	scs := keys.NewSigchainStore(dst)
	req := util.NewMockRequestor()
	ust := testStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	for i := 0; i < 10; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("a%d", i)
		testSaveUser(t, ust, scs, key, name, "github", clock, req)
		_, err := ust.Update(ctx, key.ID())
		require.NoError(t, err)
	}
	for i := 10; i < 20; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("b%d", i)
		testSaveUser(t, ust, scs, key, name, "github", clock, req)
		_, err := ust.Update(ctx, key.ID())
		require.NoError(t, err)
	}

	results, err := ust.Search(ctx, &user.SearchRequest{Query: "a"})
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, "kex18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5s0v3alm", results[0].KID.String())
	require.NotNil(t, 1, results[0].Result)
	require.Equal(t, "a0", results[0].Result.User.Name)

	results, err = ust.Search(ctx, &user.SearchRequest{Limit: 1000})
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

func mockRedditURL(url string) string {
	return url + ".json"
}
