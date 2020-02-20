package keys_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestEdX25519KeyItem(t *testing.T) {
	ks := keys.NewMemKeystore()
	sk := keys.GenerateEdX25519Key()
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

	spk := keys.GenerateEdX25519Key().PublicKey()
	err = ks.SaveSignPublicKey(spk)
	require.NoError(t, err)
	skOut, err = ks.SignKey(spk.ID())
	require.NoError(t, err)
	require.Nil(t, skOut)
}

func TestEdX25519PublicKeyItem(t *testing.T) {
	ks := keys.NewMemKeystore()
	spk := keys.GenerateEdX25519Key().PublicKey()
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

func TestFindEdX25519PublicKey(t *testing.T) {
	ks := keys.NewMemKeystore()
	sk := keys.GenerateEdX25519Key()
	err := ks.SaveSignKey(sk)
	require.NoError(t, err)

	spkConv, err := ks.FindEdX25519PublicKey(sk.PublicKey().X25519PublicKey())
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Bytes(), spkConv.Bytes())

	spk := keys.GenerateEdX25519Key().PublicKey()
	err = ks.SaveSignPublicKey(spk)
	require.NoError(t, err)

	spkConv2, err := ks.FindEdX25519PublicKey(spk.X25519PublicKey())
	require.NoError(t, err)
	require.Equal(t, spk.Bytes(), spkConv2.Bytes())
}

func TestX25519KeyItem(t *testing.T) {
	ks := keys.NewMemKeystore()
	bk := keys.GenerateX25519Key()
	err := ks.SaveBoxKey(bk)
	require.NoError(t, err)
	bkOut, err := ks.BoxKey(bk.ID())
	require.NoError(t, err)
	require.Equal(t, bk.PrivateKey()[:], bkOut.PrivateKey()[:])
	require.Equal(t, bk.PublicKey().Bytes()[:], bkOut.PublicKey().Bytes()[:])

	err = ks.SaveBoxPublicKey(bk.PublicKey())
	require.EqualError(t, err, "failed to save box public key: existing keyring item exists of alternate type")

	bpk := keys.GenerateX25519Key().PublicKey()
	err = ks.SaveBoxPublicKey(bpk)
	require.NoError(t, err)
	bkOut, err = ks.BoxKey(bpk.ID())
	require.NoError(t, err)
	require.Nil(t, bkOut)
}

func TestKeystoreList(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	ks := keys.NewMemKeystore()

	sk := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err := ks.SaveSignKey(sk)
	require.NoError(t, err)

	sk2 := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ks.SaveSignPublicKey(sk2.PublicKey())
	require.NoError(t, err)

	bk := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	err = ks.SaveBoxKey(bk)
	require.NoError(t, err)

	bk2 := keys.NewX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32)))
	err = ks.SaveBoxPublicKey(bk2.PublicKey())
	require.NoError(t, err)

	// Put passphrase in keyring to ensure it doesn't confuse us
	err = ks.Keyring().Set(keys.NewPassphraseItem("passphrase1", "password"))
	require.NoError(t, err)

	out, err := ks.Keys(nil)
	require.NoError(t, err)
	require.Equal(t, 4, len(out))

	out, err = ks.Keys(&keys.Opts{
		Types: []keys.KeyType{keys.X25519, keys.X25519Public},
	})
	require.NoError(t, err)
	require.Equal(t, 2, len(out))
	require.Equal(t, bk.ID(), out[0].ID())
	require.Equal(t, bk2.ID(), out[1].ID())

	out, err = ks.Keys(&keys.Opts{
		Types: []keys.KeyType{keys.X25519},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(out))
	require.Equal(t, bk.ID(), out[0].ID())
}

func TestKeystoreConcurrent(t *testing.T) {
	ks := keys.NewMemKeystore()
	sk := keys.GenerateEdX25519Key()
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

func TestExportImportKey(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	ks := keys.NewMemKeystore()
	err := ks.SaveKey(sk)
	require.NoError(t, err)

	password := "testpassword"
	msg, err := ks.ExportSaltpack(sk.ID(), password)
	require.NoError(t, err)

	ks2 := keys.NewMemKeystore()
	key, err := ks2.ImportSaltpack(msg, "testpassword", false)
	require.NoError(t, err)
	require.Equal(t, sk.ID(), key.ID())
}

func TestUnknownKey(t *testing.T) {
	ks := keys.NewMemKeystore()
	key, err := ks.Key(keys.RandID("kex"))
	require.NoError(t, err)
	require.Nil(t, key)
}
