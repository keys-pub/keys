package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBoxKeyFromPrivateKey(t *testing.T) {
	// Test new boxKey and boxKey from private key are the same
	boxKey := GenerateBoxKey()
	boxKeyOut := NewBoxKeyFromPrivateKey(boxKey.PrivateKey())

	require.Equal(t, boxKey.PrivateKey(), boxKeyOut.PrivateKey())
	require.Equal(t, boxKey.PublicKey(), boxKeyOut.PublicKey())
}

func TestBoxKeyConversion(t *testing.T) {
	sk := GenerateSignKey()
	bk, err := sk.BoxKey()
	require.NoError(t, err)

	bpk := sk.PublicKey().BoxPublicKey()

	require.Equal(t, bk.PublicKey().Bytes()[:], bpk.Bytes()[:])
}
