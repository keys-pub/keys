package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewX25519KeyFromPrivateKey(t *testing.T) {
	// Test new X25519Key and X25519Key from private key are the same
	X25519Key := GenerateX25519Key()
	X25519KeyOut := NewX25519KeyFromPrivateKey(X25519Key.PrivateKey())

	require.Equal(t, X25519Key.PrivateKey(), X25519KeyOut.PrivateKey())
	require.Equal(t, X25519Key.PublicKey(), X25519KeyOut.PublicKey())
}

func TestX25519KeyConversion(t *testing.T) {
	sk := GenerateEdX25519Key()
	bk := sk.X25519Key()

	bpk := sk.PublicKey().X25519PublicKey()

	require.Equal(t, bk.PublicKey().Bytes()[:], bpk.Bytes()[:])
}
