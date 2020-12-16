package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestCryptoBoxSeal(t *testing.T) {
	alice := keys.GenerateX25519Key()
	charlie := keys.GenerateX25519Key()

	plaintext := []byte("my secret message")

	encrypted := keys.CryptoBoxSeal(plaintext, alice.PublicKey())

	decrypted, err := keys.CryptoBoxSealOpen(encrypted, alice)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	_, err = keys.CryptoBoxSealOpen(encrypted, charlie)
	require.EqualError(t, err, "failed to box open")
}
