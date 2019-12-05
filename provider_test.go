package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProviderSign(t *testing.T) {
	clock := newClock()
	ks := NewMemKeystore()
	sp := newBasicSignProvider(ks)

	alice, err := ks.GenerateKey(false, clock.Now())
	require.NoError(t, err)

	// Sign
	msg := []byte("hello")
	sig, err := sp.Sign(msg, alice.SignKey())
	require.NoError(t, err)
	require.True(t, len(sig) > 0)

	// Verify
	out, signer, err := sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), SignPublicKeyID(signer))
	require.Equal(t, "hello", string(out))

	// Verify empty
	sig, err = sp.Sign([]byte{}, alice.SignKey())
	require.NoError(t, err)
	out, signer, err = sp.Verify(sig)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), SignPublicKeyID(signer))
	require.Equal(t, "", string(out))
}

func TestProviderSeal(t *testing.T) {
	clock := newClock()
	ks := NewMemKeystore()
	cp := newBasicCryptoProvider(ks)

	alice, err := ks.GenerateKey(false, clock.Now())
	require.NoError(t, err)

	bob, err := ks.GenerateKey(false, clock.Now())
	require.NoError(t, err)

	msg := []byte("hello bob, it's alice")
	encrypted, err := cp.Seal(msg, alice, bob.PublicKey())
	require.NoError(t, err)

	out, signer, err := cp.Open(encrypted)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), signer)
	require.Equal(t, msg, out)
}

func TestProviderSealRecipientNotFound(t *testing.T) {
	ks := NewMemKeystore()

	alice := GenerateKey()
	bob := GenerateKey()

	cp := newBasicCryptoProvider(ks)

	msg := []byte("hello bob, it's alice")
	encrypted, err := cp.Seal(msg, alice, bob.PublicKey())
	require.NoError(t, err)

	_, _, err = cp.Open(encrypted)
	require.EqualError(t, err, "open failed")
}
