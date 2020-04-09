package keys_test

import (
	"fmt"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestNewX25519KeyFromPrivateKey(t *testing.T) {
	// Test new X25519Key and X25519Key from private key are the same
	X25519Key := keys.GenerateX25519Key()
	X25519KeyOut := keys.NewX25519KeyFromPrivateKey(X25519Key.PrivateKey())

	require.Equal(t, X25519Key.PrivateKey(), X25519KeyOut.PrivateKey())
	require.Equal(t, X25519Key.PublicKey().Bytes(), X25519KeyOut.PublicKey().Bytes())
}

func TestX25519KeyConversion(t *testing.T) {
	sk := keys.GenerateEdX25519Key()
	bk := sk.X25519Key()

	bpk := sk.PublicKey().X25519PublicKey()

	require.Equal(t, bk.PublicKey().Bytes()[:], bpk.Bytes()[:])
}

func ExampleGenerateX25519Key() {
	alice := keys.GenerateX25519Key()
	fmt.Printf("Alice: %s\n", alice.ID())
}
