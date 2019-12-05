package keys

import (
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

	alice, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)

	ok, err := scs.SigchainExists(alice.ID())
	require.NoError(t, err)
	require.False(t, ok)

	ks := NewMemKeystore()
	ks.SetSigchainStore(scs)

	sca := GenerateSigchain(alice, clock.Now())

	// Save
	err = scs.SaveSigchain(sca)
	require.NoError(t, err)

	// Exists
	ok, err = scs.SigchainExists(alice.ID())
	require.NoError(t, err)
	require.True(t, ok)

	st, err := GenerateStatement(sca, []byte("test"), alice.SignKey(), "", clock.Now())
	require.NoError(t, err)
	err = sca.Add(st)
	require.NoError(t, err)

	// Save (update)
	err = scs.SaveSigchain(sca)
	require.NoError(t, err)

	pk, err := ks.PublicKey(alice.ID())
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.Equal(t, alice.ID(), pk.ID())

	bob, err := NewKeyFromSeedPhrase(bobSeed, false)
	require.NoError(t, err)
	err = scs.SaveSigchain(GenerateSigchain(bob, clock.Now()))
	require.NoError(t, err)

	kids, err := scs.KIDs()
	require.NoError(t, err)
	expected := []ID{
		ID("HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec"),
		ID("KNLPD1zD35FpXxP8q2B7JEWVqeJTxYH5RQKtGgrgNAtU"),
	}
	require.Equal(t, expected, kids)

	ok, err = scs.DeleteSigchain(alice.ID())
	require.NoError(t, err)
	require.True(t, ok)

	kids, err = scs.KIDs()
	require.NoError(t, err)
	expected = []ID{
		ID("KNLPD1zD35FpXxP8q2B7JEWVqeJTxYH5RQKtGgrgNAtU"),
	}
	require.Equal(t, expected, kids)

	aliceSC, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.Nil(t, aliceSC)

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

	alice, err := NewKeyFromSeedPhrase(aliceSeed, false)
	require.NoError(t, err)
	sc := GenerateSigchain(alice, clock.Now())

	st, err := GenerateStatement(sc, []byte("test1"), alice.SignKey(), "", clock.Now())
	require.NoError(t, err)
	err = scs.AddStatement(st, alice.SignKey())
	require.EqualError(t, err, "sigchain not found HX7DWqV9FtkXWJpXw656Uabtt98yjPH8iybGkfz2hvec")
	err = scs.SaveSigchain(sc)
	require.NoError(t, err)
	err = scs.AddStatement(st, alice.SignKey())
	require.NoError(t, err)

	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)

	st2, err := GenerateStatement(sc, []byte("test2"), alice.SignKey(), "", clock.Now())
	require.NoError(t, err)
	err = scs.AddStatement(st2, alice.SignKey())
	require.NoError(t, err)

	revoke, err := scs.RevokeStatement(st2.Seq, alice.SignKey())
	require.NoError(t, err)
	require.NotNil(t, revoke)

	sc, err = scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.Equal(t, 4, len(sc.Statements()))

	spew, err := sc.Spew()
	require.NoError(t, err)

	expected, err := ioutil.ReadFile("testdata/sc1.spew")
	require.NoError(t, err)
	require.Equal(t, string(expected), spew.String())
}

func TestSigchainReadOnly(t *testing.T) {
	clock := newClock()
	scs := testSigchainStore(t, clock)

	alice := GenerateKey()
	err := scs.SaveSigchain(GenerateSigchain(alice, clock.Now()))
	require.NoError(t, err)

	sc, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)
	require.NotNil(t, sc)

	st, err := GenerateStatement(sc, []byte("test1"), alice.SignKey(), "", clock.Now())
	require.NoError(t, err)

	err = sc.Add(st)
	require.EqualError(t, err, "sigchain is read only")

	err = scs.AddStatement(st, alice.SignKey())
	require.NoError(t, err)

	sc2, err := scs.Sigchain(alice.ID())
	require.NoError(t, err)

	_, err = sc2.Revoke(1, alice.SignKey())
	require.EqualError(t, err, "sigchain is read only")
}
