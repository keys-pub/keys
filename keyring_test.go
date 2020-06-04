package keys_test

import (
	"sync"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func TestX25519KeyItem(t *testing.T) {
	key := keys.GenerateX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestX25519PublicKeyItem(t *testing.T) {
	key := keys.GenerateX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key.ID()))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestEdX25519KeyItem(t *testing.T) {
	key := keys.GenerateEdX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestEdX25519PublicKeyItem(t *testing.T) {
	key := keys.GenerateEdX25519Key()
	out, err := keys.KeyForItem(keys.ItemForKey(key.ID()))
	require.NoError(t, err)
	require.Equal(t, key.ID(), out.ID())
}

func TestSaveFindDelete(t *testing.T) {
	kr := keyring.NewMem(true)
	sk := keys.GenerateEdX25519Key()
	err := keys.Save(kr, sk)
	require.NoError(t, err)
	out, err := keys.FindEdX25519Key(kr, sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.PrivateKey(), out.PrivateKey())
	require.Equal(t, sk.PublicKey().Bytes(), out.PublicKey().Bytes())

	ok, err := keys.Delete(kr, sk.ID())
	require.NoError(t, err)
	require.True(t, ok)

	out, err = keys.FindEdX25519Key(kr, sk.ID())
	require.NoError(t, err)
	require.Nil(t, out)

	ok, err = keys.Delete(kr, sk.ID())
	require.NoError(t, err)
	require.False(t, ok)
}

func TestEdX25519Key(t *testing.T) {
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))

	kr := keyring.NewMem(true)
	sk := keys.GenerateEdX25519Key()

	err := keys.Save(kr, sk)
	require.NoError(t, err)
	skOut, err := keys.FindEdX25519Key(kr, sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.PrivateKey()[:], skOut.PrivateKey()[:])
	require.Equal(t, sk.PublicKey().Bytes()[:], skOut.PublicKey().Bytes()[:])

	sks, err := keys.EdX25519Keys(kr)
	require.NoError(t, err)
	require.Equal(t, 1, len(sks))
	require.Equal(t, sk.Seed()[:], sks[0].Seed()[:])

	spk := keys.GenerateEdX25519Key().PublicKey()
	err = keys.Save(kr, spk)
	require.NoError(t, err)
	skOut, err = keys.FindEdX25519Key(kr, spk.ID())
	require.NoError(t, err)
	require.Nil(t, skOut)

	// Save again
	err = keys.Save(kr, spk)
	require.Equal(t, err, keyring.ErrItemAlreadyExists)
}

func TestFindEdX25519PublicKey(t *testing.T) {
	kr := keyring.NewMem(true)
	sk := keys.GenerateEdX25519Key()
	err := keys.Save(kr, sk)
	require.NoError(t, err)

	spkConv, err := keys.FindEdX25519PublicKey(kr, sk.PublicKey().X25519PublicKey().ID())
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Bytes(), spkConv.Bytes())

	spk := keys.GenerateEdX25519Key().PublicKey()
	err = keys.Save(kr, spk)
	require.NoError(t, err)

	spkConv2, err := keys.FindEdX25519PublicKey(kr, spk.X25519PublicKey().ID())
	require.NoError(t, err)
	require.Equal(t, spk.Bytes(), spkConv2.Bytes())
}

func TestX25519Key(t *testing.T) {
	kr := keyring.NewMem(true)
	bk := keys.GenerateX25519Key()
	err := keys.Save(kr, bk)
	require.NoError(t, err)
	bkOut, err := keys.FindX25519Key(kr, bk.ID())
	require.NoError(t, err)
	require.Equal(t, bk.PrivateKey()[:], bkOut.PrivateKey()[:])
	require.Equal(t, bk.PublicKey().Bytes()[:], bkOut.PublicKey().Bytes()[:])

	err = keys.Save(kr, bk.PublicKey())
	require.EqualError(t, err, "keyring item already exists")

	bpk := keys.GenerateX25519Key().PublicKey()
	err = keys.Save(kr, bpk)
	require.NoError(t, err)
	bkOut, err = keys.FindX25519Key(kr, bpk.ID())
	require.NoError(t, err)
	require.Nil(t, bkOut)
}

func TestList(t *testing.T) {
	// SetLogger(NewLogger(DebugLevel))
	kr := keyring.NewMem(true)

	sk := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	err := keys.Save(kr, sk)
	require.NoError(t, err)

	sk2 := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	err = keys.Save(kr, sk2.PublicKey())
	require.NoError(t, err)

	bk := keys.NewX25519KeyFromSeed(testSeed(0x01))
	err = keys.Save(kr, bk)
	require.NoError(t, err)

	bk2 := keys.NewX25519KeyFromSeed(testSeed(0x02))
	err = keys.Save(kr, bk2.PublicKey())
	require.NoError(t, err)

	out, err := keys.Keys(kr)
	require.NoError(t, err)
	require.Equal(t, 4, len(out))

	out, err = keys.Keys(kr, keys.WithTypes(keys.X25519, keys.X25519Public))
	require.NoError(t, err)
	require.Equal(t, 2, len(out))
	require.Equal(t, bk.ID(), out[0].ID())
	require.Equal(t, bk2.ID(), out[1].ID())

	out, err = keys.Keys(kr, keys.WithTypes(keys.X25519))
	require.NoError(t, err)
	require.Equal(t, 1, len(out))
	require.Equal(t, bk.ID(), out[0].ID())
}

func TestStoreConcurrent(t *testing.T) {
	kr := keyring.NewMem(true)
	sk := keys.GenerateEdX25519Key()
	err := keys.Save(kr, sk)
	require.NoError(t, err)

	skOut, err := keys.FindEdX25519Key(kr, sk.ID())
	require.NoError(t, err)
	require.Equal(t, sk.Seed()[:], skOut.Seed()[:])

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for i := 0; i < 2000; i++ {
			skOut, err := keys.FindEdX25519Key(kr, sk.ID())
			require.NoError(t, err)
			require.Equal(t, sk.Seed()[:], skOut.Seed()[:])
		}
		wg.Done()
	}()
	for i := 0; i < 2000; i++ {
		skOut, err := keys.FindEdX25519Key(kr, sk.ID())
		require.NoError(t, err)
		require.Equal(t, sk.Seed()[:], skOut.Seed()[:])
	}
	wg.Wait()
}

func TestExportImportKey(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	kr := keyring.NewMem(true)
	err := keys.Save(kr, sk)
	require.NoError(t, err)

	password := "testpassword"
	msg, err := keys.ExportSaltpack(kr, sk.ID(), password)
	require.NoError(t, err)

	kr2 := keyring.NewMem(true)
	key, err := keys.ImportSaltpack(kr2, msg, "testpassword", false)
	require.NoError(t, err)
	require.Equal(t, sk.ID(), key.ID())
}

func TestUnknownKey(t *testing.T) {
	kr := keyring.NewMem(true)
	key, err := keys.Find(kr, keys.RandID("kex"))
	require.NoError(t, err)
	require.Nil(t, key)
}
