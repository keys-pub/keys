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

// TODO: Don't accept user names on server > some length

func TestSearchUsers(t *testing.T) {
	//SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := NewMem()
	dst.SetTimeNow(clock.Now)
	scs := newSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	req := NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	results, err := ust.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)
	// Add alice@github
	saveUser(t, ust, scs, alice, "alice", "github", clock, req)

	ids := []ID{}
	for i := 10; i < 15; i++ {
		key, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		ids = append(ids, key.ID())
		name := fmt.Sprintf("name%d", i)
		saveUser(t, ust, scs, key, name, "github", clock, req)
		_, err = ust.Update(ctx, key.ID())
		require.NoError(t, err)
	}

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = ust.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "github", results[0].Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Users[0].User.URL)
	require.Equal(t, 1, results[0].Users[0].User.Seq)
	require.Equal(t, TimeMs(1234567890034), results[0].Users[0].VerifiedAt)
	require.Equal(t, TimeMs(1234567890033), results[0].Users[0].Timestamp)

	// Add alicenew@github
	aliceNewSt := saveUser(t, ust, scs, alice, "alicenew", "github", clock, req)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = ust.Search(ctx, &SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 2, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "github", results[0].Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Users[0].User.URL)
	require.Equal(t, 1, results[0].Users[0].User.Seq)
	require.Equal(t, "alicenew", results[0].Users[1].User.Name)
	require.Equal(t, "github", results[0].Users[1].User.Service)
	require.Equal(t, "https://gist.github.com/alicenew/1", results[0].Users[1].User.URL)
	require.Equal(t, 2, results[0].Users[1].User.Seq)

	// Revoke alice, update
	sc, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	_, err = sc.Revoke(1, alice)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alicenew", results[0].Users[0].User.Name)
	require.Equal(t, "github", results[0].Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alicenew/1", results[0].Users[0].User.URL)
	require.Equal(t, 2, results[0].Users[0].User.Seq)

	// Add alice@twitter
	alice2, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x03}, 32)))
	require.NoError(t, err)
	saveUser(t, ust, scs, alice2, "alice", Twitter, clock, req)
	_, err = ust.Update(ctx, alice2.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, Twitter, results[0].Users[0].User.Service)
	require.Equal(t, 1, results[0].Users[0].User.Seq)
	require.Equal(t, 1, len(results[1].Users))
	require.Equal(t, alice.ID(), results[1].Users[0].User.KID)
	require.Equal(t, "alicenew", results[1].Users[0].User.Name)
	require.Equal(t, "github", results[1].Users[0].User.Service)
	require.Equal(t, 2, results[1].Users[0].User.Seq)

	// Revoke alicenew@github
	_, err = sc.Revoke(aliceNewSt.Seq, alice)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, Twitter, results[0].Users[0].User.Service)

	results, err = ust.Search(ctx, &SearchRequest{Query: "alice@twitter"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, Twitter, results[0].Users[0].User.Service)

	results, err = ust.Search(ctx, &SearchRequest{Query: alice2.ID().String()[:5]})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, Twitter, results[0].Users[0].User.Service)

	results, err = ust.Search(ctx, &SearchRequest{Query: alice2.ID().String()[:5], Fields: []SearchField{KIDField}})
	require.NoError(t, err)
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice2.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, Twitter, results[0].Users[0].User.Service)

	results, err = ust.Search(ctx, &SearchRequest{Query: ids[0].String()[:5], Fields: []SearchField{KIDField}})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, ids[0].String(), results[0].KID.String())

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
	ust := testUserStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	results, err := ust.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	alice, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)
	// Add alice@github
	saveUser(t, ust, scs, alice, "alice", "github", clock, req)

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err = ust.Search(ctx, &SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)

	// Set error for alice@github
	data, err := req.Response("https://gist.github.com/alice/1")
	require.NoError(t, err)
	req.SetError("https://gist.github.com/alice/1", errors.Errorf("test error"))
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	results, err = ust.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID().String(), results[0].KID.String())

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
	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)

	results, err = ust.Search(ctx, &SearchRequest{Query: "alice@github"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID().String(), results[0].KID.String())
}

func TestExpired(t *testing.T) {
	dst := NewMem()
	scs := NewSigchainStore(dst)

	clock := newClock()
	req := NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	ids, err := ust.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	alice, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)
	// Add alice@github
	saveUser(t, ust, scs, alice, "alice", "github", clock, req)

	_, err = ust.Update(ctx, alice.ID())
	require.NoError(t, err)
	results, err := ust.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, alice.ID(), results[0].Users[0].User.KID)
	require.Equal(t, "alice", results[0].Users[0].User.Name)
	require.Equal(t, "github", results[0].Users[0].User.Service)
	require.Equal(t, "https://gist.github.com/alice/1", results[0].Users[0].User.URL)
	require.Equal(t, 1, results[0].Users[0].User.Seq)
	require.Equal(t, TimeMs(1234567890003), results[0].Users[0].VerifiedAt)
	require.Equal(t, TimeMs(1234567890002), results[0].Users[0].Timestamp)

	ids, err = ust.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	ids, err = ust.Expired(ctx, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, []ID{alice.ID()}, ids)
}

func saveUser(t *testing.T, ust *UserStore, scs SigchainStore, key *SignKey, name string, service string, clock *clock, mock *MockRequestor) *Statement {
	url := ""
	switch service {
	case Github:
		url = fmt.Sprintf("https://gist.github.com/%s/1", name)
	case Twitter:
		url = fmt.Sprintf("https://twitter.com/%s/status/1", name)
	default:
		t.Fatal("unsupported service in test")
	}

	sc, err := scs.Sigchain(key.ID())
	require.NoError(t, err)
	if sc == nil {
		sc = NewSigchain(key.PublicKey())
	}

	user, err := NewUser(ust, key.ID(), service, name, url, sc.LastSeq()+1)
	require.NoError(t, err)

	st, err := GenerateUserStatement(sc, user, key, clock.Now())
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
	dst := NewMem()
	scs := NewSigchainStore(dst)
	key, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	require.NoError(t, err)

	req := NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	sc := NewSigchain(key.PublicKey())
	user, err := NewUser(ust, key.ID(), "github", "alice", "https://gist.github.com/alice/1", 1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, user, key, clock.Now())
	require.NoError(t, err)
	require.Equal(t, st.Seq, user.Seq)

	user, err = NewUser(ust, key.ID(), "github", "alice", "https://gist.github.com/alice/1", 100)
	require.NoError(t, err)
	_, err = GenerateUserStatement(sc, user, key, clock.Now())
	require.EqualError(t, err, "user seq mismatch")
}

func TestSearch(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	req := NewMockRequestor()
	ust := testUserStore(t, dst, scs, req, clock)
	ctx := context.TODO()

	for i := 0; i < 10; i++ {
		key, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		name := fmt.Sprintf("a%d", i)
		saveUser(t, ust, scs, key, name, "github", clock, req)
	}
	for i := 10; i < 20; i++ {
		key, err := NewSignKeyFromSeed(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		name := fmt.Sprintf("b%d", i)
		saveUser(t, ust, scs, key, name, "github", clock, req)
	}

	kids, kerr := scs.KIDs()
	require.NoError(t, kerr)
	require.Equal(t, 20, len(kids))
	for _, kid := range kids {
		_, err := ust.Update(ctx, kid)
		require.NoError(t, err)
	}

	results, err := ust.Search(ctx, &SearchRequest{Query: "a"})
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, "ed18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5svmehft", results[0].KID.String())
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, "a0", results[0].Users[0].User.Name)

	results, err = ust.Search(ctx, &SearchRequest{Query: "a", Limit: 2})
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, "ed18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5svmehft", results[0].KID.String())
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, "a0", results[0].Users[0].User.Name)

	results, err = ust.Search(ctx, &SearchRequest{Limit: 1000})
	require.NoError(t, err)
	require.Equal(t, 20, len(results))
	require.Equal(t, "ed1vmxkpzuj3wyw2rswl64r87h3cs7wlcrjjjctsl5luz46dg70wces3kq4ef", results[19].KID.String())
	require.Equal(t, 1, len(results[19].Users))
}
