package keys

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	secretKey := GenerateSecretKey()
	err := ks.SaveSecretKey("key1", secretKey)
	require.NoError(t, err)
	item, err := ks.Get("key1")
	require.NoError(t, err)
	require.Equal(t, secretKey[:], item.SecretData())
}

func TestSignKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	signKey := GenerateSignKey()
	err := ks.SaveSignKey(signKey)
	require.NoError(t, err)
	signKeyOut, err := ks.SignKey(signKey.ID())
	require.NoError(t, err)
	require.Equal(t, signKey.PrivateKey()[:], signKeyOut.PrivateKey()[:])
	require.Equal(t, signKey.PublicKey().Bytes()[:], signKeyOut.PublicKey().Bytes()[:])
}

func TestBoxKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	boxKey := GenerateBoxKey()
	err := ks.SaveBoxKey(boxKey)
	require.NoError(t, err)
	boxKeyOut, err := ks.BoxKey(boxKey.ID())
	require.NoError(t, err)
	require.Equal(t, boxKey.PrivateKey()[:], boxKeyOut.PrivateKey()[:])
	require.Equal(t, boxKey.PublicKey()[:], boxKeyOut.PublicKey()[:])
}

func TestCertificateKeyItem(t *testing.T) {
	ks := NewMemKeystore()
	cert, err := GenerateCertificateKey("Test", true, nil)
	require.NoError(t, err)
	err = ks.SaveCertificateKey("cert1", cert)
	require.NoError(t, err)
	certOut, err := ks.CertificateKey("cert1")
	require.NoError(t, err)
	require.Equal(t, cert.Private(), certOut.Private())
	require.Equal(t, cert.Public(), certOut.Public())
}

func TestKeystoreList(t *testing.T) {
	ks := NewMemKeystore()
	for i := 0; i < 10; i++ {
		err := ks.SavePassphrase(fmt.Sprintf("p%d", i), "passphrase")
		require.NoError(t, err)
	}
	key := GenerateBoxKey()
	err := ks.SaveBoxKey(key)
	require.NoError(t, err)

	items, err := ks.List()
	require.NoError(t, err)
	require.Equal(t, 11, len(items))
}

func TestKeystoreConcurrent(t *testing.T) {
	ks := NewMemKeystore()
	secretKey := Rand32()
	ks.SaveSecretKey("key1", secretKey)

	sk, err := ks.SecretKey("key1")
	require.NoError(t, err)
	require.Equal(t, secretKey[:], sk[:])

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for i := 0; i < 2000; i++ {
			sk, err := ks.SecretKey("key1")
			require.NoError(t, err)
			require.Equal(t, secretKey[:], sk[:])
		}
		wg.Done()
	}()
	for i := 0; i < 2000; i++ {
		sk, err := ks.SecretKey("key1")
		require.NoError(t, err)
		require.Equal(t, secretKey[:], sk[:])
	}
	wg.Wait()
}
