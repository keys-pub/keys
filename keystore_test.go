package keys

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	sk := GenerateSignKey()
	err := ks.SaveSignKey(sk)
	require.NoError(t, err)
	skOut, err := ks.SignKey(sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.PrivateKey()[:], skOut.PrivateKey()[:])
	require.Equal(t, sk.PublicKey().Bytes()[:], skOut.PublicKey().Bytes()[:])

	sks, err := ks.SignKeys()
	require.NoError(t, err)
	require.Equal(t, 1, len(sks))
	require.Equal(t, sk.Seed()[:], sks[0].Seed()[:])

	spkOut, err := ks.SignPublicKey(sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Bytes()[:], spkOut.Bytes()[:])

	err = ks.SaveSignPublicKey(sk.PublicKey())
	require.EqualError(t, err, "failed to save sign public key: existing keyring item exists of alternate type")

	spk := GenerateSignKey().PublicKey()
	err = ks.SaveSignPublicKey(spk)
	require.NoError(t, err)
	skOut, err = ks.SignKey(spk.ID())
	require.NoError(t, err)
	require.Nil(t, skOut)
}

func TestSignPublicKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	spk := GenerateSignKey().PublicKey()
	err := ks.SaveSignPublicKey(spk)
	require.NoError(t, err)
	spkOut, err := ks.SignPublicKey(spk.ID())
	require.NoError(t, err)
	require.Equal(t, spk.Bytes()[:], spkOut.Bytes()[:])

	spks, err := ks.SignPublicKeys()
	require.NoError(t, err)
	require.Equal(t, 1, len(spks))
	require.Equal(t, spk.Bytes()[:], spks[0].Bytes()[:])
}

func TestBoxKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	bk := GenerateBoxKey()
	err := ks.SaveBoxKey(bk)
	require.NoError(t, err)
	bkOut, err := ks.BoxKey(bk.ID())
	require.NoError(t, err)
	require.Equal(t, bk.PrivateKey()[:], bkOut.PrivateKey()[:])
	require.Equal(t, bk.PublicKey().Bytes()[:], bkOut.PublicKey().Bytes()[:])

	err = ks.SaveBoxPublicKey(bk.PublicKey())
	require.EqualError(t, err, "failed to save box public key: existing keyring item exists of alternate type")

	bpk := GenerateBoxKey().PublicKey()
	err = ks.SaveBoxPublicKey(bpk)
	require.NoError(t, err)
	bkOut, err = ks.BoxKey(bpk.ID())
	require.NoError(t, err)
	require.Nil(t, bkOut)
}

func TestKeystoreList(t *testing.T) {
	ks := NewMemKeystore()
	for i := 0; i < 10; i++ {
		sk := GenerateSignKey()
		err := ks.SaveSignKey(sk)
		require.NoError(t, err)
	}
	bk := GenerateBoxKey()
	err := ks.SaveBoxKey(bk)
	require.NoError(t, err)

	out, err := ks.Keys(nil)
	require.NoError(t, err)
	require.Equal(t, 10, len(out.SignKeys))
	require.Equal(t, 1, len(out.BoxKeys))
}

func TestKeystoreConcurrent(t *testing.T) {
	ks := NewMemKeystore()
	sk := GenerateSignKey()
	ks.SaveSignKey(sk)

	skOut, err := ks.SignKey(sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.Seed()[:], skOut.Seed()[:])

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for i := 0; i < 2000; i++ {
			skOut, err := ks.SignKey(sk.ID())
			require.NoError(t, err)
			require.Equal(t, sk.Seed()[:], skOut.Seed()[:])
		}
		wg.Done()
	}()
	for i := 0; i < 2000; i++ {
		skOut, err := ks.SignKey(sk.ID())
		require.NoError(t, err)
		require.Equal(t, sk.Seed()[:], skOut.Seed()[:])
	}
	wg.Wait()
}
