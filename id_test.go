package keys_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/stretchr/testify/require"
)

func TestID(t *testing.T) {
	b := bytes.Repeat([]byte{0xFF}, 32)
	s := encoding.MustEncode(b[:], encoding.Base58)
	require.Equal(t, "osEoy933LkHyyBcgjE7v81KvmcNKioeUVktgzXLJ1B3t", s)
	require.Equal(t, 44, len(s))

	b = bytes.Repeat([]byte{0x00}, 32)
	s = encoding.MustEncode(b[:], encoding.Base58)
	require.Equal(t, "11111111111111111111111111111111111111111111", s)
	require.Equal(t, 44, len(s))
}

func TestNewID(t *testing.T) {
	n := 10000
	m := make(map[keys.ID]bool, n)
	for i := 0; i < n; i++ {
		b := keys.Rand32()
		id, err := keys.NewID("test", b[:])
		require.NoError(t, err)
		if _, ok := m[id]; ok {
			t.Fatalf("id collision %s", id)
		}
		m[id] = true
	}
}

func TestIDSet(t *testing.T) {
	s := keys.NewIDSet(keys.ID("a"), keys.ID("b"), keys.ID("c"))
	require.True(t, s.Contains(keys.ID("a")))
	require.False(t, s.Contains(keys.ID("z")))
	s.Add("z")
	require.True(t, s.Contains(keys.ID("z")))
	s.Add("z")
	require.Equal(t, 4, s.Size())
	s.AddAll([]keys.ID{"m", "n"})

	expected := []keys.ID{keys.ID("a"), keys.ID("b"), keys.ID("c"), keys.ID("z"), keys.ID("m"), keys.ID("n")}
	require.Equal(t, expected, s.IDs())

	s.Clear()
	require.False(t, s.Contains(keys.ID("a")))
	require.False(t, s.Contains(keys.ID("z")))
	require.Equal(t, 0, s.Size())
}
