package keys

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestID(t *testing.T) {
	b := bytes.Repeat([]byte{0xFF}, 32)
	s := MustEncode(b[:], Base58)
	require.Equal(t, "osEoy933LkHyyBcgjE7v81KvmcNKioeUVktgzXLJ1B3t", s)
	require.Equal(t, 44, len(s))

	b = bytes.Repeat([]byte{0x00}, 32)
	s = MustEncode(b[:], Base58)
	require.Equal(t, "11111111111111111111111111111111111111111111", s)
	require.Equal(t, 44, len(s))
}

func TestEncodeID(t *testing.T) {
	n := 10000
	m := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		b := randBytes(32)
		id, err := encodeID(b[:])
		require.NoError(t, err)
		if _, ok := m[id]; ok {
			t.Fatalf("id collision %s", id)
		}
		m[id] = true
	}
}
