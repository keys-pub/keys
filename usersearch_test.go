package keys_test

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

// TODO: Don't accept user names on server > some length

func TestSearchUsers(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := keys.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := keys.NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	results, err := ust.Search(ctx, &keys.UserSearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)
	// Add alice@github
	saveUser(t, ust, scs, alice, "alice", "github", clock, req)

	ids := []keys.ID{}
	for i := 10; i < 15; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		ids = append(ids, key.ID())
		name := fmt.Sprintf("name%d", i)
		saveUser(t, ust, scs, key, name, "github", clock, req)
		_, err = ust.Update(ctx, key.ID())
		require.NoError(t, err)
	}

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].UserResult)
	require.Equal(t, alice.ID(), results[0].UserResult.User.KID)
	require.Equal(t, "alice", results[0].UserResult.User.Name)
	require.Equal(t, "github", results[0].UserResult.User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].UserResult.User.URL)
	require.Equal(t, 1, results[0].UserResult.User.Seq)
	require.Equal(t, keys.TimeMs(1234567890034), results[0].UserResult.VerifiedAt)
	require.Equal(t, keys.TimeMs(1234567890033), results[0].UserResult.Timestamp)

	// Revoke alice, update
	sc, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Add alicenew@github
	aliceNewSt := saveUser(t, ust, scs, alice, "alicenew", "github", clock, req)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	// Search "al", match "alicenew".
	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].UserResult)
	require.Equal(t, "alicenew", results[0].UserResult.User.Name)
	require.Equal(t, "github", results[0].UserResult.User.Service)
	require.Equal(t, "https://gist.github.com/alicenew/1", results[0].UserResult.User.URL)
	require.Equal(t, 3, results[0].UserResult.User.Seq)

	// Add alice@twitter
	alice2 := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x03}, 32)))
	saveUser(t, ust, scs, alice2, "alice", keys.Twitter, clock, req)
	_, err = ust.Update(ctx, alice2.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.NotNil(t, results[0].UserResult)
	require.Equal(t, alice2.ID(), results[0].UserResult.User.KID)
	require.Equal(t, "alice", results[0].UserResult.User.Name)
	require.Equal(t, keys.Twitter, results[0].UserResult.User.Service)
	require.Equal(t, 1, results[0].UserResult.User.Seq)
	require.NotNil(t, results[1].UserResult)
	require.Equal(t, alice.ID(), results[1].UserResult.User.KID)
	require.Equal(t, "alicenew", results[1].UserResult.User.Name)
	require.Equal(t, "github", results[1].UserResult.User.Service)
	require.Equal(t, 3, results[1].UserResult.User.Seq)

	// Revoke alicenew@github
	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)
	_, err = sc.Revoke(aliceNewSt.Seq, alice)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].UserResult.User.KID)
	require.Equal(t, "alice", results[0].UserResult.User.Name)
	require.Equal(t, keys.Twitter, results[0].UserResult.User.Service)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alice@twitter"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].UserResult.User.KID)
	require.Equal(t, "alice", results[0].UserResult.User.Name)
	require.Equal(t, keys.Twitter, results[0].UserResult.User.Service)

	// Check Documents
	iter, err := dst.Documents(context.TODO(), "kid", nil)
	require.NoError(t, err)
	spew, err := keys.Spew(iter, nil)
	require.NoError(t, err)
	expected, err := ioutil.ReadFile("testdata/kid.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())

	iter, err = dst.Documents(context.TODO(), "user", nil)
	require.NoError(t, err)
	spew, err = keys.Spew(iter, nil)
	require.NoError(t, err)
	expected, err = ioutil.ReadFile("testdata/user.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())
}

func TestSearchUsersRequestErrors(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := keys.NewMem()
	dst.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := keys.NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	results, err := ust.Search(ctx, &keys.UserSearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	// Add alice@github
	saveUser(t, ust, scs, alice, "alice", "github", clock, req)

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].UserResult)
	require.Equal(t, alice.ID(), results[0].KID)
	require.Equal(t, keys.TimeMs(1234567890003), results[0].UserResult.Timestamp)
	require.Equal(t, keys.TimeMs(1234567890004), results[0].UserResult.VerifiedAt)

	data, err := req.Response("https://gist.github.com/alice/1")
	require.NoError(t, err)

	// Set 500 error for alice@github
	req.SetError("https://gist.github.com/alice/1", keys.ErrHTTP{StatusCode: 500})
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.NotNil(t, results[0].UserResult)
	require.Equal(t, keys.UserStatusConnFailure, results[0].UserResult.Status)
	require.Equal(t, keys.TimeMs(1234567890007), results[0].UserResult.Timestamp)
	require.Equal(t, keys.TimeMs(1234567890004), results[0].UserResult.VerifiedAt)

	// Set 404 error for alice@github
	req.SetError("https://gist.github.com/alice/1", keys.ErrHTTP{StatusCode: 404})
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	// Check Documents
	iter, err := dst.Documents(context.TODO(), "kid", nil)
	require.NoError(t, err)
	spew, err := keys.Spew(iter, nil)
	require.NoError(t, err)
	expected, err := ioutil.ReadFile("testdata/kid2.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())

	iter, err = dst.Documents(context.TODO(), "user", nil)
	require.NoError(t, err)
	spew, err = keys.Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, "", spew.String())

	// Unset error
	req.SetResponse("https://gist.github.com/alice/1", data)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID().String(), results[0].KID.String())
}

func TestExpired(t *testing.T) {
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)

	clock := newClock()
	req := keys.NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
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
	saveUser(t, ust, scs, alice, "alice", "github", clock, req)

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err := ust.Search(ctx, &keys.UserSearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID(), results[0].UserResult.User.KID)
	require.Equal(t, "alice", results[0].UserResult.User.Name)
	require.Equal(t, "github", results[0].UserResult.User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].UserResult.User.URL)
	require.Equal(t, 1, results[0].UserResult.User.Seq)
	require.Equal(t, keys.TimeMs(1234567890003), results[0].UserResult.VerifiedAt)
	require.Equal(t, keys.TimeMs(1234567890002), results[0].UserResult.Timestamp)

	ids, err = ust.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	ids, err = ust.Expired(ctx, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, []keys.ID{alice.ID()}, ids)
}

func saveUser(t *testing.T, ust *keys.UserStore, scs keys.SigchainStore, key *keys.SignKey, name string, service string, clock *clock, mock *keys.MockRequestor) *keys.Statement {
	url := ""
	switch service {
	case keys.Github:
		url = fmt.Sprintf("https://gist.github.com/%s/1", name)
	case keys.Twitter:
		url = fmt.Sprintf("https://twitter.com/%s/status/1", name)
	default:
		t.Fatal("unsupported service in test")
	}

	sc, err := scs.Sigchain(key.ID())
	require.NoError(t, err)
	if sc == nil {
		sc = keys.NewSigchain(key.PublicKey())
	}

	user, err := keys.NewUser(ust, key.ID(), service, name, url, sc.LastSeq()+1)
	require.NoError(t, err)

	st, err := keys.GenerateUserStatement(sc, user, key, clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)

	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	msg, err := user.Sign(key)
	require.NoError(t, err)
	mock.SetResponse(url, []byte(msg))

	return st
}

func TestGenerateUserStatement(t *testing.T) {
	clock := newClock()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	req := keys.NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	sc := keys.NewSigchain(key.PublicKey())
	user, err := keys.NewUser(ust, key.ID(), "github", "alice", "https://gist.github.com/alice/1", 1)
	require.NoError(t, err)
	st, err := keys.GenerateUserStatement(sc, user, key, clock.Now())
	require.NoError(t, err)
	require.Equal(t, st.Seq, user.Seq)

	user, err = keys.NewUser(ust, key.ID(), "github", "alice", "https://gist.github.com/alice/1", 100)
	require.NoError(t, err)
	_, err = keys.GenerateUserStatement(sc, user, key, clock.Now())
	require.EqualError(t, err, "user seq mismatch")
}

func TestSearch(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	clock := newClock()
	dst := keys.NewMem()
	scs := keys.NewSigchainStore(dst)
	req := keys.NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	for i := 0; i < 10; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("a%d", i)
		saveUser(t, ust, scs, key, name, "github", clock, req)
		_, err := ust.Update(ctx, key.ID())
		require.NoError(t, err)
	}
	for i := 10; i < 20; i++ {
		key := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		name := fmt.Sprintf("b%d", i)
		saveUser(t, ust, scs, key, name, "github", clock, req)
		_, err := ust.Update(ctx, key.ID())
		require.NoError(t, err)
	}

	results, err := ust.Search(ctx, &keys.UserSearchRequest{Query: "a"})
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, "kex18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5s0v3alm", results[0].KID.String())
	require.NotNil(t, 1, results[0].UserResult)
	require.Equal(t, "a0", results[0].UserResult.User.Name)

	results, err = ust.Search(ctx, &keys.UserSearchRequest{Limit: 1000})
	require.NoError(t, err)
	require.Equal(t, 20, len(results))
	require.Equal(t, "kex18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5s0v3alm", results[0].KID.String())
}
