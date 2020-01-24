package keys

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func testSigchainStore(t *testing.T, clock *clock) SigchainStore {
	mem := NewMem()
	mem.SetTimeNow(clock.Now)
	scs := newSigchainStore(mem)
	scs.SetTimeNow(clock.Now)
	return scs
}

func TestSigchainStore(t *testing.T) {
	clock := newClock()
	scs := testSigchainStore(t, clock)

	alice := NewEd25519KeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))

	ok, err := scs.SigchainExists(alice.ID())
	require.NoError(t, err)
	require.False(t, ok)

	sc, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.NotNil(t, sc)

	sca := NewSigchain(alice.PublicKey())
	st, err := GenerateStatement(sca, []byte("alice"), alice, "", clock.Now())
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

	st, err = GenerateStatement(sca, []byte("alice2"), alice, "", clock.Now())
	require.NoError(t, err)
	err = sca.Add(st)
	require.NoError(t, err)

	// Save (update)
	err = scs.SaveSigchain(sca)
	require.NoError(t, err)

	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.NotNil(t, sc)
	require.Equal(t, alice.ID(), sc.ID())

	bob := NewEd25519KeyFromSeed(Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	scb := NewSigchain(bob.PublicKey())
	st, err = GenerateStatement(scb, []byte("bob"), bob, "", clock.Now())
	require.NoError(t, err)
	err = scb.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(scb)
	require.NoError(t, err)

	kids, err := scs.KIDs()
	require.NoError(t, err)
	expected := []ID{
		alice.ID(),
		bob.ID(),
	}
	require.Equal(t, expected, kids)

	ok, err = scs.DeleteSigchain(alice.ID())
	require.NoError(t, err)
	require.True(t, ok)

	kids, err = scs.KIDs()
	require.NoError(t, err)
	expected = []ID{
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
	clock := newClock()
	scs := testSigchainStore(t, clock)

	alice := NewEd25519KeyFromSeed(Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	sc := NewSigchain(alice.PublicKey())

	st, err := GenerateStatement(sc, []byte("test1"), alice, "", clock.Now())
	require.NoError(t, err)
	err = sc.Add(st)
	require.NoError(t, err)
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)

	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)

	st2, err := GenerateStatement(sc, []byte("test2"), alice, "", clock.Now())
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

	spew, err := sc.Spew()
	require.NoError(t, err)

	expected, err := ioutil.ReadFile("testdata/sc1.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())
}
