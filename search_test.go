package keys

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

var ctx = context.TODO()

// TODO: Don't accept user names on server > some length

func TestSearchUsers(t *testing.T) {
	//SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := NewMem()
	dst.SetTimeNow(clock.Now)
	scs := newSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)
	search := NewSearch(dst, scs, uc)

	results, err := search.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(alice, clock.Now()))
	require.NoError(t, err)

	// Add alice@github
	saveUser(t, uc, scs, alice, "alice", "github", clock, req)

	for i := 0; i < 5; i++ {
		key, err := NewKey(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		sc := GenerateSigchain(key, clock.Now())
		err = scs.SaveSigchain(sc)
		require.NoError(t, err)
		name := fmt.Sprintf("name%d", i)
		saveUser(t, uc, scs, key, name, "github", clock, req)
		err = search.Update(ctx, sc.ID())
		require.NoError(t, err)
	}

	for i := 5; i < 7; i++ {
		key, err := NewKey(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		sc := GenerateSigchain(key, clock.Now())
		err = scs.SaveSigchain(sc)
		require.NoError(t, err)
		err = search.Update(ctx, sc.ID())
		require.NoError(t, err)
	}

	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = search.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "github", results[0].Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Users[0].User.URL)
	require.Equal(t, 2, results[0].Users[0].User.Seq)

	res, err := search.Get(ctx, alice.ID())
	require.NoError(t, err)
	require.Equal(t, 1, len(res.Users))
	require.Equal(t, "alice", res.Users[0].User.Name)
	require.Equal(t, "github", res.Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", res.Users[0].User.URL)
	require.Equal(t, 2, res.Users[0].User.Seq)
	require.Equal(t, TimeMs(1234567890052), TimeToMillis(res.Users[0].VerifiedAt))
	require.Equal(t, TimeMs(1234567890051), TimeToMillis(res.Users[0].Timestamp))

	// Add alicenew@github
	aliceNewSt := saveUser(t, uc, scs, alice, "alicenew", "github", clock, req)
	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = search.Search(ctx, &SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 2, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "github", results[0].Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Users[0].User.URL)
	require.Equal(t, 2, results[0].Users[0].User.Seq)
	require.Equal(t, "alicenew", results[0].Users[1].User.Name)
	require.Equal(t, "github", results[0].Users[1].User.Service)
	require.Equal(t, "https://gist.github.com/alicenew/1", results[0].Users[1].User.URL)
	require.Equal(t, 3, results[0].Users[1].User.Seq)

	// Revoke alice, update
	_, err = scs.RevokeStatement(2, alice.SignKey())
	require.NoError(t, err)
	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alicenew", results[0].Users[0].User.Name)
	require.Equal(t, "github", results[0].Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alicenew/1", results[0].Users[0].User.URL)
	require.Equal(t, 3, results[0].Users[0].User.Seq)

	// Add alice@twitter
	alice2, err := NewKeyFromSeedPhrase(aliceSeed2, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(alice2, clock.Now()))
	require.NoError(t, err)
	saveUser(t, uc, scs, alice2, "alice", "twitter", clock, req)
	err = search.Update(ctx, alice2.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "twitter", results[0].Users[0].User.Service)
	require.Equal(t, 2, results[0].Users[0].User.Seq)
	require.Equal(t, 1, len(results[1].Users))
	require.Equal(t, alice.ID(), results[1].Users[0].User.KID)
	require.Equal(t, "alicenew", results[1].Users[0].User.Name)
	require.Equal(t, "github", results[1].Users[0].User.Service)
	require.Equal(t, 3, results[1].Users[0].User.Seq)

	// Revoke alicenew@github
	_, err = scs.RevokeStatement(aliceNewSt.Seq, alice.SignKey())
	require.NoError(t, err)
	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "twitter", results[0].Users[0].User.Service)

	results, err = search.Search(ctx, &SearchRequest{Query: "alice@twitter"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "twitter", results[0].Users[0].User.Service)

	results, err = search.Search(ctx, &SearchRequest{Query: "ELjdt5eDPyAB"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)

	results, err = search.Search(ctx, &SearchRequest{Query: "ELjdt5eDPyAB", Fields: []SearchField{KIDField}})
	require.NoError(t, err)
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "twitter", results[0].Users[0].User.Service)

	results, err = search.Search(ctx, &SearchRequest{Query: "HX7DWqV9Ftk", Fields: []SearchField{KIDField}})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, "HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec", results[0].KID.String())

	// Check Documents
	iter, err := dst.Documents(context.TODO(), "kid", nil)
	require.NoError(t, err)
	spew, err := Spew(iter, nil)
	require.NoError(t, err)
	expected, err := ioutil.ReadFile("testdata/kid.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())

	iter, err = dst.Documents(context.TODO(), "user", nil)
	require.NoError(t, err)
	spew, err = Spew(iter, nil)
	require.NoError(t, err)
	expected, err = ioutil.ReadFile("testdata/user.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())
}

func TestSearchUsersRequestErrors(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := NewMem()
	dst.SetTimeNow(clock.Now)
	scs := newSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)
	search := NewSearch(dst, scs, uc)

	results, err := search.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(alice, clock.Now()))
	require.NoError(t, err)

	// Add alice@github
	saveUser(t, uc, scs, alice, "alice", "github", clock, req)

	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = search.Search(ctx, &SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)

	// Set error for alice@github
	data, err := req.Response("https://gist.github.com/alice/1")
	require.NoError(t, err)
	req.SetError("https://gist.github.com/alice/1", errors.Errorf("test error"))
	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	results, err = search.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, "HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec", results[0].KID.String())

	// Check Documents
	iter, err := dst.Documents(context.TODO(), "kid", nil)
	require.NoError(t, err)
	spew, err := Spew(iter, nil)
	require.NoError(t, err)
	expected, err := ioutil.ReadFile("testdata/kid2.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())

	iter, err = dst.Documents(context.TODO(), "user", nil)
	require.NoError(t, err)
	spew, err = Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, "", spew.String())

	// Unset error
	req.SetResponse("https://gist.github.com/alice/1", data)
	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, "HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec", results[0].KID.String())
}

func TestExpired(t *testing.T) {
	dst := NewMem()
	scs := NewSigchainStore(dst)

	clock := newClock()
	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)
	search := NewSearch(dst, scs, uc)

	ids, err := search.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	alice, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(alice, clock.Now()))
	require.NoError(t, err)

	saveUser(t, uc, scs, alice, "alice", "github", clock, req)

	bob, err := NewKeyFromSeedPhrase(bobSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(bob, clock.Now()))
	require.NoError(t, err)

	err = search.Update(ctx, alice.ID())
	require.NoError(t, err)
	result, err := search.Get(ctx, alice.ID())
	require.NoError(t, err)
	require.Equal(t, 1, len(result.Users))
	require.Equal(t, alice.ID(), result.Users[0].User.KID)
	require.Equal(t, "alice", result.Users[0].User.Name)
	require.Equal(t, "github", result.Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", result.Users[0].User.URL)
	require.Equal(t, 2, result.Users[0].User.Seq)
	require.Equal(t, TimeFromMillis(1234567890005), result.Users[0].VerifiedAt)
	require.Equal(t, TimeFromMillis(1234567890004), result.Users[0].Timestamp)

	ids, err = search.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	ids, err = search.Expired(ctx, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, []ID{alice.ID()}, ids)
}

func TestRevoke(t *testing.T) {
	clock := newClock()
	scs := NewSigchainStore(NewMem())

	alice, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)

	err = scs.SaveSigchain(GenerateSigchain(alice, clock.Now()))
	require.NoError(t, err)

	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)

	_ = saveUser(t, uc, scs, alice, "alice", "github", clock, req)
	st := saveUser(t, uc, scs, alice, "alicenew", "github", clock, req)

	_, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)

	_, err = scs.RevokeStatement(st.Seq, alice.SignKey())
	require.NoError(t, err)
}

func saveUser(t *testing.T, uc *UserContext, scs SigchainStore, key Key, name string, service string, clock *clock, mock *MockRequestor) *Statement {
	sc, err := scs.Sigchain(key.ID())
	require.NoError(t, err)
	require.NotNil(t, sc)
	url := ""
	switch service {
	case "github":
		url = fmt.Sprintf("https://gist.github.com/%s/1", name)
	case "twitter":
		url = fmt.Sprintf("https://twitter.com/%s/status/1", name)
	default:
		t.Fatal("unsupported service in test")
	}

	user, err := NewUser(uc, key.ID(), service, name, url, sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, user, key.SignKey(), clock.Now())
	require.NoError(t, err)
	err = scs.AddStatement(st, key.SignKey())
	require.NoError(t, err)

	msg, err := user.Sign(key.SignKey())
	require.NoError(t, err)
	mock.SetResponse(url, []byte(msg))

	return st
}

func TestGenerateStatement(t *testing.T) {
	clock := newClock()
	scs := NewSigchainStore(NewMem())
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()
	err = scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
	require.NoError(t, err)
	sc, err := scs.Sigchain(kid)
	require.NoError(t, err)
	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)
	user, err := NewUser(uc, kid, "github", "alice", "https://gist.github.com/alice/1", 2)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, user, key.SignKey(), clock.Now())
	require.NoError(t, err)
	require.Equal(t, st.Seq, user.Seq)

	user, err = NewUser(uc, kid, "github", "alice", "https://gist.github.com/alice/1", 100)
	require.NoError(t, err)
	_, err = GenerateUserStatement(sc, user, key.SignKey(), clock.Now())
	require.EqualError(t, err, "user seq mismatch")
}

func TestSearch(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	req := NewMockRequestor()
	uc := NewTestUserContext(req, clock.Now)
	search := NewSearch(dst, scs, uc)

	for i := 0; i < 10; i++ {
		key, err := NewKey(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		err = scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
		require.NoError(t, err)
		name := fmt.Sprintf("a%d", i)
		saveUser(t, uc, scs, key, name, "github", clock, req)
	}
	for i := 10; i < 20; i++ {
		key, err := NewKey(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		err = scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
		require.NoError(t, err)
		name := fmt.Sprintf("b%d", i)
		saveUser(t, uc, scs, key, name, "github", clock, req)
	}
	for i := 20; i < 256; i++ {
		key, err := NewKey(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		err = scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
		require.NoError(t, err)
		name := fmt.Sprintf("c%d", i)
		saveUser(t, uc, scs, key, name, "github", clock, req)
	}

	kids, kerr := scs.KIDs()
	require.NoError(t, kerr)
	require.Equal(t, 256, len(kids))
	for _, kid := range kids {
		err := search.Update(ctx, kid)
		require.NoError(t, err)
	}

	results, err := search.Search(ctx, &SearchRequest{Query: "a", Limit: 11})
	require.NoError(t, err)
	require.Equal(t, 11, len(results))
	require.Equal(t, "ddRZXkYg1VcHRhpR6zu5kPBzsSLV9sJTWkTdduCJu2yu", results[0].KID.String())
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, "a0", results[0].Users[0].User.Name)
	require.Equal(t, "aBMAH6R9eih6pdMNiDxJYUtprt9GLzWVTiXwHAqktXrj", results[10].KID.String())

	results, err = search.Search(ctx, &SearchRequest{Query: "a", Limit: 2})
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, "ddRZXkYg1VcHRhpR6zu5kPBzsSLV9sJTWkTdduCJu2yu", results[0].KID.String())
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, "a0", results[0].Users[0].User.Name)

	results, err = search.Search(ctx, &SearchRequest{Limit: 1000})
	require.NoError(t, err)
	require.Equal(t, 256, len(results))
}
