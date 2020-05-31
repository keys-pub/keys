package keys_test

import (
	"sync"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestEdX25519Key(t *testing.T) {
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))

	ks := keys.NewMemStore(true)
	sk := keys.GenerateEdX25519Key()

	err := ks.Save(sk)
	require.NoError(t, err)
	skOut, err := ks.EdX25519Key(sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.PrivateKey()[:], skOut.PrivateKey()[:])
	require.Equal(t, sk.PublicKey().Bytes()[:], skOut.PublicKey().Bytes()[:])

	sks, err := ks.EdX25519Keys()
	require.NoError(t, err)
	require.Equal(t, 1, len(sks))
	require.Equal(t, sk.Seed()[:], sks[0].Seed()[:])

	spkOut, err := ks.EdX25519PublicKey(sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Bytes()[:], spkOut.Bytes()[:])

	err = ks.Save(sk.PublicKey())
	require.EqualError(t, err, "keyring item already exists")

	spk := keys.GenerateEdX25519Key().PublicKey()
	err = ks.Save(spk)
	require.NoError(t, err)
	skOut, err = ks.EdX25519Key(spk.ID())
	require.NoError(t, err)
	require.Nil(t, skOut)

	// Save again
	err = ks.Save(spk)
	require.Equal(t, err, keyring.ErrItemAlreadyExists)
}

func TestEdX25519PublicKey(t *testing.T) {
	ks := keys.NewMemStore(true)
	spk := keys.GenerateEdX25519Key().PublicKey()
	err := ks.Save(spk)
	require.NoError(t, err)
	spkOut, err := ks.EdX25519PublicKey(spk.ID())
	require.NoError(t, err)
	require.Equal(t, spk.Bytes()[:], spkOut.Bytes()[:])

	spks, err := ks.EdX25519PublicKeys()
	require.NoError(t, err)
	require.Equal(t, 1, len(spks))
	require.Equal(t, spk.Bytes()[:], spks[0].Bytes()[:])
}

func TestFindEdX25519PublicKey(t *testing.T) {
	ks := keys.NewMemStore(true)
	sk := keys.GenerateEdX25519Key()
	err := ks.Save(sk)
	require.NoError(t, err)

	spkConv, err := ks.FindEdX25519PublicKey(sk.PublicKey().X25519PublicKey().ID())
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Bytes(), spkConv.Bytes())

	spk := keys.GenerateEdX25519Key().PublicKey()
	err = ks.Save(spk)
	require.NoError(t, err)

	spkConv2, err := ks.FindEdX25519PublicKey(spk.X25519PublicKey().ID())
	require.NoError(t, err)
	require.Equal(t, spk.Bytes(), spkConv2.Bytes())
}

func TestX25519Key(t *testing.T) {
	ks := keys.NewMemStore(true)
	bk := keys.GenerateX25519Key()
	err := ks.Save(bk)
	require.NoError(t, err)
	bkOut, err := ks.X25519Key(bk.ID())
	require.NoError(t, err)
	require.Equal(t, bk.PrivateKey()[:], bkOut.PrivateKey()[:])
	require.Equal(t, bk.PublicKey().Bytes()[:], bkOut.PublicKey().Bytes()[:])

	err = ks.Save(bk.PublicKey())
	require.EqualError(t, err, "keyring item already exists")

	bpk := keys.GenerateX25519Key().PublicKey()
	err = ks.Save(bpk)
	require.NoError(t, err)
	bkOut, err = ks.X25519Key(bpk.ID())
	require.NoError(t, err)
	require.Nil(t, bkOut)
}

func TestStoreList(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	ks := keys.NewMemStore(true)

	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	err := ks.Save(sk)
	require.NoError(t, err)

	sk2 := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	err = ks.Save(sk2.PublicKey())
	require.NoError(t, err)

	bk := keys.NewX25519KeyFromSeed(testSeed(0x01))
	err = ks.Save(bk)
	require.NoError(t, err)

	bk2 := keys.NewX25519KeyFromSeed(testSeed(0x02))
	err = ks.Save(bk2.PublicKey())
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

func TestStoreConcurrent(t *testing.T) {
	ks := keys.NewMemStore(true)
	sk := keys.GenerateEdX25519Key()
	err := ks.Save(sk)
	require.NoError(t, err)

	skOut, err := ks.EdX25519Key(sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.Seed()[:], skOut.Seed()[:])

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for i := 0; i < 2000; i++ {
			skOut, err := ks.EdX25519Key(sk.ID())
			require.NoError(t, err)
			require.Equal(t, sk.Seed()[:], skOut.Seed()[:])
		}
		wg.Done()
	}()
	for i := 0; i < 2000; i++ {
		skOut, err := ks.EdX25519Key(sk.ID())
		require.NoError(t, err)
		require.Equal(t, sk.Seed()[:], skOut.Seed()[:])
	}
	wg.Wait()
}

func TestExportImportKey(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	ks := keys.NewMemStore(true)
	err := ks.Save(sk)
	require.NoError(t, err)

	password := "testpassword"
	msg, err := ks.ExportSaltpack(sk.ID(), password)
	require.NoError(t, err)

	ks2 := keys.NewMemStore(true)
	key, err := ks2.ImportSaltpack(msg, "testpassword", false)
	require.NoError(t, err)
	require.Equal(t, sk.ID(), key.ID())
}

func TestUnknownKey(t *testing.T) {
	ks := keys.NewMemStore(true)
	key, err := ks.Key(keys.RandID("kex"))
	require.NoError(t, err)
	require.Nil(t, key)
}
