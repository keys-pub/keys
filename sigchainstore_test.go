package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/ds"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func testSigchainStore(t *testing.T, clock *tsutil.Clock) keys.SigchainStore {
	mem := ds.NewMem()
	mem.SetTimeNow(clock.Now)
	scs := keys.NewSigchainStore(mem)
	scs.SetTimeNow(clock.Now)
	return scs
}

func TestSigchainStore(t *testing.T) {
	clock := tsutil.NewClock()
	scs := testSigchainStore(t, clock)

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	ok, err := scs.SigchainExists(alice.ID())
	require.NoError(t, err)
	require.False(t, ok)

	sc, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.NotNil(t, sc)

	sca := keys.NewSigchain(alice.ID())
	st, err := keys.NewSigchainStatement(sca, []byte("alice"), alice, "", clock.Now())
	require.NoError(t, err)
	err = sca.Add(st)
	require.NoError(t, err)

	// Save
	err = scs.SaveSigchain(sca)
	require.NoError(t, err)

	// Exists
	ok, err = scs.SigchainExists(alice.ID())
	require.NoError(t, err)
	require.True(t, ok)

	st, err = keys.NewSigchainStatement(sca, []byte("alice2"), alice, "", clock.Now())
	require.NoError(t, err)
	err = sca.Add(st)
	require.NoError(t, err)

	// Save (update)
	err = scs.SaveSigchain(sca)
	require.NoError(t, err)

	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.Equal(t, alice.ID(), sc.KID())

	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	scb := keys.NewSigchain(bob.ID())
	st, err = keys.NewSigchainStatement(scb, []byte("bob"), bob, "", clock.Now())
	require.NoError(t, err)
	err = scb.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(scb)
	require.NoError(t, err)

	kids, err := scs.KIDs()
	require.NoError(t, err)
	expected := []keys.ID{
		alice.ID(),
		bob.ID(),
	}
	require.Equal(t, expected, kids)

	ok, err = scs.DeleteSigchain(alice.ID())
	require.NoError(t, err)
	require.True(t, ok)

	kids, err = scs.KIDs()
	require.NoError(t, err)
	expected = []keys.ID{
		bob.ID(),
	}
	require.Equal(t, expected, kids)

	ok, err = scs.SigchainExists(alice.ID())
	require.NoError(t, err)
	require.False(t, ok)

	ok, err = scs.DeleteSigchain(alice.ID())
	require.NoError(t, err)
	require.False(t, ok)
}

func TestSigchainStoreSpew(t *testing.T) {
	clock := tsutil.NewClock()
	scs := testSigchainStore(t, clock)

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	sc := keys.NewSigchain(alice.ID())

	st, err := keys.NewSigchainStatement(sc, []byte("test1"), alice, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)

	st2, err := keys.NewSigchainStatement(sc, []byte("test2"), alice, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st2)
	require.NoError(t, err)

	revoke, err := sc.Revoke(st2.Seq, alice)
	require.NoError(t, err)
	require.NotNil(t, revoke)

	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.Equal(t, 3, len(sc.Statements()))

	spew := sc.Spew()
	require.Equal(t, testdataString(t, "testdata/sc1.spew"), spew.String())
}
