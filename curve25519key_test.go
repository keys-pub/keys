package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCurve25519KeyFromPrivateKey(t *testing.T) {
	// Test new Curve25519Key and Curve25519Key from private key are the same
	Curve25519Key := GenerateCurve25519Key()
	Curve25519KeyOut := NewCurve25519KeyFromPrivateKey(Curve25519Key.PrivateKey())

	require.Equal(t, Curve25519Key.PrivateKey(), Curve25519KeyOut.PrivateKey())
	require.Equal(t, Curve25519Key.PublicKey(), Curve25519KeyOut.PublicKey())
}

func TestCurve25519KeyConversion(t *testing.T) {
	sk := GenerateEd25519Key()
	bk := sk.Curve25519Key()

	bpk := sk.PublicKey().Curve25519PublicKey()

	require.Equal(t, bk.PublicKey().Bytes()[:], bpk.Bytes()[:])
}
