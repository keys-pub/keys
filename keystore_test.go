package keys

import (
	"sync"
	"testing"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

const aliceSeed = "win rebuild update term layer transfer gain field prepare unique spider cool present argue grab trend eagle casino peace hockey loop seed desert swear"
const bobSeed = "crane chimney shell unique drink dynamic math pilot letter inflict tattoo curtain primary crystal live return affair husband general cargo chat vintage demand deer"

func TestKeystoreSaveKey(t *testing.T) {
	ks := NewMemKeystore()
	clock := newClock()
	key := GenerateKey()
	err := ks.SaveKey(key, false, clock.Now())
	require.NoError(t, err)
	item, err := ks.Get(key.ID())
	require.NoError(t, err)
	require.Equal(t, key.Seed()[:], item.SecretData())

	keyOut, err := ks.Key(key.ID())
	require.NoError(t, err)
	require.Equal(t, key.Seed()[:], keyOut.Seed()[:])
}

func TestKeystoreSaveSecretKey(t *testing.T) {
	ks := NewMemKeystore()
	secretKey := GenerateSecretKey()
	kid := RandID()
	err := ks.SaveSecretKey(kid, secretKey)
	require.NoError(t, err)
	item, err := ks.Get(kid)
	require.NoError(t, err)
	require.Equal(t, secretKey[:], item.SecretData())
}

func TestKeystoreList(t *testing.T) {
	clock := newClock()
	scs := newSigchainStore(NewMem())
	scs.SetTimeNow(clock.Now)
	ks := NewMemKeystore()
	ks.SetSigchainStore(scs)
	for i := 0; i < 10; i++ {
		err := ks.SavePassphrase(RandID(), "passphrase")
		require.NoError(t, err)
	}
	key, err := ks.GenerateKey(true, clock.Now())
	require.NoError(t, err)

	items, err := ks.List(nil)
	require.NoError(t, err)
	require.Equal(t, 11, len(items))

	items, err = ks.List(&keyring.ListOpts{Type: KeyType})
	require.NoError(t, err)
	require.Equal(t, 1, len(items))
	require.Equal(t, key.ID().String(), items[0].ID)
}

func TestKeystoreConcurrent(t *testing.T) {
	ks := NewMemKeystore()
	kid := RandID()
	secretKey, err := ks.GenerateSecretKey(kid)
	require.NoError(t, err)

	sk, err := ks.SecretKey(kid)
	require.NoError(t, err)
	require.Equal(t, secretKey[:], sk[:])

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for i := 0; i < 2000; i++ {
			sk, err := ks.SecretKey(kid)
			require.NoError(t, err)
			require.Equal(t, secretKey[:], sk[:])
		}
		wg.Done()
	}()
	for i := 0; i < 2000; i++ {
		sk, err := ks.SecretKey(kid)
		require.NoError(t, err)
		require.Equal(t, secretKey[:], sk[:])
	}
	wg.Wait()
}

func TestSignKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	signKey := GenerateSignKey()
	err := ks.SaveSignKey(signKey)
	require.NoError(t, err)
	signKeyOut, err := ks.SignKey(signKey.ID)
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey()[:], signKeyOut.PrivateKey()[:])
	require.Equal(t, signKey.PublicKey[:], signKeyOut.PublicKey[:])
}

func TestBoxKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	boxKey := GenerateBoxKey()
	err := ks.SaveBoxKey(boxKey)
	require.NoError(t, err)
	boxKeyOut, err := ks.BoxKey(boxKey.ID)
	require.NoError(t, err)
	require.Equal(t, boxKey.PrivateKey()[:], boxKeyOut.PrivateKey()[:])
	require.Equal(t, boxKey.PublicKey[:], boxKeyOut.PublicKey[:])
}

func TestCertificateKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	cert, err := GenerateCertificateKey("Test", true, nil)
	require.NoError(t, err)
	id := RandID()
	err = ks.SaveCertificateKey(id, cert)
	require.NoError(t, err)
	certOut, err := ks.CertificateKey(id)
	require.NoError(t, err)
	require.Equal(t, cert.Private(), certOut.Private())
	require.Equal(t, cert.Public(), certOut.Public())
}
