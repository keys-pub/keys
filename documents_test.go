package keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocumentStoreSign(t *testing.T) {
	scs := newSigchainStore(NewMem())
	ks := NewMemKeystore()
	ks.SetSigchainStore(scs)
	ctx := context.TODO()
	mem := NewMem()
	cp := newBasicCryptoProvider(ks)
	dst := NewCryptoStore(mem, cp)
	clock := newClock()
	scs.SetTimeNow(clock.Now)
	dst.SetTimeNow(clock.Now)

	alice, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)

	// Sign
	msgID := RandID()
	msg := []byte("hello")
	path := Path("message", msgID)
	out, err := dst.Sign(ctx, path, msg, alice.SignKey())
	require.NoError(t, err)
	require.True(t, len(out) > 0)

	// Verify
	verified, err := dst.Verify(ctx, path)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), verified.Signer)
	require.Equal(t, "hello", string(verified.Data))

	// Verify empty
	si2, siErr2 := dst.Sign(ctx, "test/1", []byte{}, alice.SignKey())
	require.NoError(t, siErr2)
	require.NotNil(t, si2)
	_, err = dst.Verify(ctx, "test/1")
	require.NoError(t, err)
}

func TestDocumentStoreSeal(t *testing.T) {
	clock := newClock()
	scs := newSigchainStore(NewMem())
	scs.SetTimeNow(clock.Now)
	ks := NewMemKeystore()
	ks.SetSigchainStore(scs)
	ctx := context.TODO()
	mem := NewMem()
	cp := newBasicCryptoProvider(ks)
	dst := NewCryptoStore(mem, cp)

	alice, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)

	bob, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)

	id := RandID()
	path := Path("message", id)
	_, err = dst.Seal(ctx, path, []byte("hello"), alice, bob.PublicKey())
	require.NoError(t, err)

	opened, err := dst.Open(ctx, path)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), opened.Signer)
	require.Equal(t, "hello", string(opened.Data))
}
