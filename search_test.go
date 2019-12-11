package keys

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var ctx = context.TODO()

// TODO: Don't accept user names on server > some length

func TestSearchUsers(t *testing.T) {
	EnableServices("test", "test2")
	// SetLogger(NewLogger(DebugLevel))

	clock := newClock()
	dst := NewMem()
	dst.SetTimeNow(clock.Now)
	scs := newSigchainStore(dst)
	scs.SetTimeNow(clock.Now)

	search := NewSearch(dst, scs)
	search.SetNowFn(clock.Now)

	results, err := search.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 0, len(results))

	aliceTest, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(aliceTest, clock.Now()))
	require.NoError(t, err)

	// Add alice@test
	saveUser(t, scs, aliceTest, "alice", "test", clock)

	for i := 0; i < 5; i++ {
		key, err := NewKey(Bytes32(bytes.Repeat([]byte{byte(i)}, 32)))
		require.NoError(t, err)
		sc := GenerateSigchain(key, clock.Now())
		err = scs.SaveSigchain(sc)
		require.NoError(t, err)
		name := fmt.Sprintf("name%d", i)
		saveUser(t, scs, key, name, "test", clock)
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

	err = search.Update(ctx, aliceTest.ID())
	require.NoError(t, err)
	results, err = search.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, aliceTest.ID(), results[0].Users[0].KID)
	require.Equal(t, "alice", results[0].Users[0].Name)
	require.Equal(t, "test", results[0].Users[0].Service)
	require.Equal(t, "test:", results[0].Users[0].URL)
	require.Equal(t, 2, results[0].Users[0].Seq)

	res, err := search.Get(ctx, aliceTest.ID())
	require.NoError(t, err)
	require.Equal(t, 1, len(res.Users))
	require.Equal(t, "alice", res.Users[0].Name)
	require.Equal(t, "test", res.Users[0].Service)
	require.Equal(t, "test:", res.Users[0].URL)
	require.Equal(t, 2, res.Users[0].Seq)
	require.Equal(t, TimeMs(1234567890046), TimeToMillis(res.Users[0].CheckedAt))

	// Add alicenew@test
	aliceNewSt := saveUser(t, scs, aliceTest, "alicenew", "test", clock)
	err = search.Update(ctx, aliceTest.ID())
	require.NoError(t, err)
	results, err = search.Search(ctx, &SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 2, len(results[0].Users))
	require.Equal(t, aliceTest.ID(), results[0].Users[0].KID)
	require.Equal(t, "alice", results[0].Users[0].Name)
	require.Equal(t, "test", results[0].Users[0].Service)
	require.Equal(t, "test:", results[0].Users[0].URL)
	require.Equal(t, 2, results[0].Users[0].Seq)
	require.Equal(t, "alicenew", results[0].Users[1].Name)
	require.Equal(t, "test", results[0].Users[1].Service)
	require.Equal(t, "test:", results[0].Users[1].URL)
	require.Equal(t, 3, results[0].Users[1].Seq)

	// Revoke alice, update
	_, err = scs.RevokeStatement(2, aliceTest.SignKey())
	require.NoError(t, err)
	err = search.Update(ctx, aliceTest.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "al"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, aliceTest.ID(), results[0].Users[0].KID)
	require.Equal(t, "alicenew", results[0].Users[0].Name)
	require.Equal(t, "test", results[0].Users[0].Service)
	require.Equal(t, "test:", results[0].Users[0].URL)
	require.Equal(t, 3, results[0].Users[0].Seq)

	// Add alice@test2
	aliceTest2, err := NewKeyFromSeedPhrase(bobSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(aliceTest2, clock.Now()))
	require.NoError(t, err)
	saveUser(t, scs, aliceTest2, "alice", "test2", clock)
	err = search.Update(ctx, aliceTest2.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 2, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, aliceTest2.ID(), results[0].Users[0].KID)
	require.Equal(t, "alice", results[0].Users[0].Name)
	require.Equal(t, "test2", results[0].Users[0].Service)
	require.Equal(t, 2, results[0].Users[0].Seq)
	require.Equal(t, 1, len(results[1].Users))
	require.Equal(t, aliceTest.ID(), results[1].Users[0].KID)
	require.Equal(t, "alicenew", results[1].Users[0].Name)
	require.Equal(t, "test", results[1].Users[0].Service)
	require.Equal(t, 3, results[1].Users[0].Seq)

	// Revoke alicenew@test
	_, err = scs.RevokeStatement(aliceNewSt.Seq, aliceTest.SignKey())
	require.NoError(t, err)
	err = search.Update(ctx, aliceTest.ID())
	require.NoError(t, err)

	results, err = search.Search(ctx, &SearchRequest{Query: "alic"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, aliceTest2.ID(), results[0].Users[0].KID)
	require.Equal(t, "alice", results[0].Users[0].Name)
	require.Equal(t, "test2", results[0].Users[0].Service)

	results, err = search.Search(ctx, &SearchRequest{Query: "alice@test2"})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, aliceTest2.ID(), results[0].Users[0].KID)
	require.Equal(t, "alice", results[0].Users[0].Name)
	require.Equal(t, "test2", results[0].Users[0].Service)

	results, err = search.Search(ctx, &SearchRequest{Query: "KNLPD1zD35FpXx", KIDs: true})
	require.NoError(t, err)
	require.Equal(t, 1, len(results[0].Users))
	require.Equal(t, aliceTest2.ID(), results[0].Users[0].KID)
	require.Equal(t, "alice", results[0].Users[0].Name)
	require.Equal(t, "test2", results[0].Users[0].Service)

	results, err = search.Search(ctx, &SearchRequest{Query: "HX7DWqV9Ftk", KIDs: true})
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
	require.Equal(t, "HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec", results[0].KID.String())

	iter, err := dst.Documents(context.TODO(), "kid", nil)
	require.NoError(t, err)
	spew, err := Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, `/kid/CsqTWvaEmrzVc8bgmnzLJdDzVp5gCLC7nayXzqQjKCLc {"kid":"CsqTWvaEmrzVc8bgmnzLJdDzVp5gCLC7nayXzqQjKCLc","users":[{"kid":"CsqTWvaEmrzVc8bgmnzLJdDzVp5gCLC7nayXzqQjKCLc","name":"name3","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.030-08:00"}]}
/kid/FLRMd2Fb3e745YkkP9FVybgp68AV5ALSENjpzs1PfVj6 {"kid":"FLRMd2Fb3e745YkkP9FVybgp68AV5ALSENjpzs1PfVj6","users":[{"kid":"FLRMd2Fb3e745YkkP9FVybgp68AV5ALSENjpzs1PfVj6","name":"name4","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.037-08:00"}]}
/kid/HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec {"kid":"HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec"}
/kid/KNLPD1zD35FpXxP8q2B7JEWVqeJTxYH5RQKtGgrgNAtU {"kid":"KNLPD1zD35FpXxP8q2B7JEWVqeJTxYH5RQKtGgrgNAtU","users":[{"kid":"KNLPD1zD35FpXxP8q2B7JEWVqeJTxYH5RQKtGgrgNAtU","name":"alice","seq":2,"service":"test2","url":"test:","ucts":"2009-02-13T15:31:30.064-08:00"}]}
/kid/QcCryFxU6wcYxQ4DME9PP1kbq76nf2YtAqk2GwHQqfqR {"kid":"QcCryFxU6wcYxQ4DME9PP1kbq76nf2YtAqk2GwHQqfqR","users":[{"kid":"QcCryFxU6wcYxQ4DME9PP1kbq76nf2YtAqk2GwHQqfqR","name":"name1","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.016-08:00"}]}
/kid/bUCJPpR1ueFkKLS6RutSHUGviZ1UyXqU1FopbWhMCAoG {"kid":"bUCJPpR1ueFkKLS6RutSHUGviZ1UyXqU1FopbWhMCAoG"}
/kid/ddRZXkYg1VcHRhpR6zu5kPBzsSLV9sJTWkTdduCJu2yu {"kid":"ddRZXkYg1VcHRhpR6zu5kPBzsSLV9sJTWkTdduCJu2yu","users":[{"kid":"ddRZXkYg1VcHRhpR6zu5kPBzsSLV9sJTWkTdduCJu2yu","name":"name0","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.009-08:00"}]}
/kid/eP3FsGENP2WtyMqFH2udDhG2MLMeozZJUF6oZHt6Geo6 {"kid":"eP3FsGENP2WtyMqFH2udDhG2MLMeozZJUF6oZHt6Geo6","users":[{"kid":"eP3FsGENP2WtyMqFH2udDhG2MLMeozZJUF6oZHt6Geo6","name":"name2","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.023-08:00"}]}
/kid/mJAHJmJZ5tMLENXJ4ZqyDA5JLp1TcfGn2uvgxfU2rbGf {"kid":"mJAHJmJZ5tMLENXJ4ZqyDA5JLp1TcfGn2uvgxfU2rbGf"}
`, spew.String())

	iter, err = dst.Documents(context.TODO(), "user", nil)
	require.NoError(t, err)
	spew, err = Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, `/user/alice@test2 {"kid":"KNLPD1zD35FpXxP8q2B7JEWVqeJTxYH5RQKtGgrgNAtU","users":[{"kid":"KNLPD1zD35FpXxP8q2B7JEWVqeJTxYH5RQKtGgrgNAtU","name":"alice","seq":2,"service":"test2","url":"test:","ucts":"2009-02-13T15:31:30.064-08:00"}]}
/user/name0@test  {"kid":"ddRZXkYg1VcHRhpR6zu5kPBzsSLV9sJTWkTdduCJu2yu","users":[{"kid":"ddRZXkYg1VcHRhpR6zu5kPBzsSLV9sJTWkTdduCJu2yu","name":"name0","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.009-08:00"}]}
/user/name1@test  {"kid":"QcCryFxU6wcYxQ4DME9PP1kbq76nf2YtAqk2GwHQqfqR","users":[{"kid":"QcCryFxU6wcYxQ4DME9PP1kbq76nf2YtAqk2GwHQqfqR","name":"name1","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.016-08:00"}]}
/user/name2@test  {"kid":"eP3FsGENP2WtyMqFH2udDhG2MLMeozZJUF6oZHt6Geo6","users":[{"kid":"eP3FsGENP2WtyMqFH2udDhG2MLMeozZJUF6oZHt6Geo6","name":"name2","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.023-08:00"}]}
/user/name3@test  {"kid":"CsqTWvaEmrzVc8bgmnzLJdDzVp5gCLC7nayXzqQjKCLc","users":[{"kid":"CsqTWvaEmrzVc8bgmnzLJdDzVp5gCLC7nayXzqQjKCLc","name":"name3","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.030-08:00"}]}
/user/name4@test  {"kid":"FLRMd2Fb3e745YkkP9FVybgp68AV5ALSENjpzs1PfVj6","users":[{"kid":"FLRMd2Fb3e745YkkP9FVybgp68AV5ALSENjpzs1PfVj6","name":"name4","seq":2,"service":"test","url":"test:","ucts":"2009-02-13T15:31:30.037-08:00"}]}
`, spew.String())
}

func TestExpired(t *testing.T) {
	EnableServices("test")
	dst := NewMem()
	scs := NewSigchainStore(dst)

	clock := newClock()
	search := NewSearch(dst, scs)
	search.SetNowFn(clock.Now)

	aliceTest, aliceTeerr := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, aliceTeerr)
	err := scs.SaveSigchain(GenerateSigchain(aliceTest, clock.Now()))
	require.NoError(t, err)

	saveUser(t, scs, aliceTest, "alice", "test", clock)

	bob, err := NewKeyFromSeedPhrase(bobSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(bob, clock.Now()))
	require.NoError(t, err)

	err = search.Update(ctx, aliceTest.ID())
	require.NoError(t, err)
	result, err := search.Get(ctx, aliceTest.ID())
	require.NoError(t, err)
	require.Equal(t, 1, len(result.Users))
	require.Equal(t, aliceTest.ID(), result.Users[0].KID)
	require.Equal(t, "alice", result.Users[0].Name)
	require.Equal(t, "test", result.Users[0].Service)
	require.Equal(t, "test:", result.Users[0].URL)
	require.Equal(t, 2, result.Users[0].Seq)
	require.Equal(t, TimeFromMillis(1234567890004), result.Users[0].CheckedAt)

	ids, err := search.Expired(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

	ids, err = search.Expired(ctx, time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, []ID{aliceTest.ID()}, ids)
}

func TestRevoke(t *testing.T) {
	EnableServices("test")
	clock := newClock()
	scs := NewSigchainStore(NewMem())

	aliceTest, aliceTeerr := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, aliceTeerr)
	err := scs.SaveSigchain(GenerateSigchain(aliceTest, clock.Now()))
	require.NoError(t, err)

	_ = saveUser(t, scs, aliceTest, "alice", "test", clock)
	aliceSt2 := saveUser(t, scs, aliceTest, "alicenew", "test", clock)

	_, err = scs.Sigchain(aliceTest.ID())
	require.NoError(t, err)

	_, err = scs.RevokeStatement(aliceSt2.Seq, aliceTest.SignKey())
	require.NoError(t, err)
}

func saveUser(t *testing.T, scs SigchainStore, key Key, name string, service string, clock *clock) *Statement {
	sc, err := scs.Sigchain(key.ID())
	require.NoError(t, err)
	require.NotNil(t, sc)
	usr, err := NewUser(key.ID(), service, name, "test://", sc.LastSeq()+1)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, usr, key.SignKey(), clock.Now())
	require.NoError(t, err)
	err = scs.AddStatement(st, key.SignKey())
	require.NoError(t, err)
	return st
}

func TestGenerateStatement(t *testing.T) {
	EnableServices("test")
	clock := newClock()
	scs := NewSigchainStore(NewMem())
	key, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	kid := key.ID()
	err = scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
	require.NoError(t, err)
	sc, err := scs.Sigchain(kid)
	require.NoError(t, err)
	usr, err := NewUser(kid, "test", "alice", "test://", 2)
	require.NoError(t, err)
	st, err := GenerateUserStatement(sc, usr, key.SignKey(), clock.Now())
	require.NoError(t, err)
	require.Equal(t, st.Seq, usr.Seq)

	usr, err = NewUser(kid, "test", "alice", "test://", 100)
	require.NoError(t, err)
	_, err = GenerateUserStatement(sc, usr, key.SignKey(), clock.Now())
	require.EqualError(t, err, "user seq mismatch")
}

func TestSearch(t *testing.T) {
	EnableServices("test")
	clock := newClock()
	dst := NewMem()
	scs := NewSigchainStore(dst)
	search := NewSearch(dst, scs)

	for i := 0; i < 10; i++ {
		key := GenerateKey()
		err := scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
		require.NoError(t, err)
		name := "a" + RandUsername(7)
		saveUser(t, scs, key, name, "test", clock)
	}
	for i := 0; i < 10; i++ {
		key := GenerateKey()
		err := scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
		require.NoError(t, err)
		name := "b" + RandUsername(7)
		saveUser(t, scs, key, name, "test", clock)
	}
	for i := 0; i < 10; i++ {
		key := GenerateKey()
		err := scs.SaveSigchain(GenerateSigchain(key, clock.Now()))
		require.NoError(t, err)
		name := "c" + RandUsername(7)
		saveUser(t, scs, key, name, "test", clock)
	}

	kids, kerr := scs.KIDs()
	require.NoError(t, kerr)
	require.Equal(t, 30, len(kids))
	for _, kid := range kids {
		err := search.Update(ctx, kid)
		require.NoError(t, err)
	}

	results, err := search.Search(ctx, &SearchRequest{Query: "a"})
	require.NoError(t, err)
	require.Equal(t, 10, len(results))
	require.Equal(t, 1, len(results[0].Users))
	require.True(t, strings.HasPrefix(results[0].Users[0].Name, "a"))

	results, err = search.Search(ctx, &SearchRequest{})
	require.NoError(t, err)
	require.Equal(t, 30, len(results))

	results, err = search.Search(ctx, &SearchRequest{Index: 21})
	require.NoError(t, err)
	require.Equal(t, 9, len(results))
}
