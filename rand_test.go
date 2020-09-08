package keys_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestRandID(t *testing.T) {
	kid := keys.RandID("test")
	require.False(t, strings.Contains(kid.String(), "="))
}

func TestRandBytes(t *testing.T) {
	b1 := keys.RandBytes(32)
	require.Equal(t, 32, len(b1))
	for i := 0; i < 1000; i++ {
		b2 := keys.RandBytes(32)
		require.False(t, bytes.Equal(b1, b2))
	}
}

func TestRandWords(t *testing.T) {
	p6 := keys.RandWords(6)
	require.Equal(t, 6, len(strings.Split(p6, " ")))
	require.Panics(t, func() { keys.RandWords(0) })

	p1 := keys.RandWords(24)
	require.Equal(t, 24, len(strings.Split(p1, " ")))
	require.Panics(t, func() { keys.RandWords(25) })

	for i := 0; i < 1000; i++ {
		p2 := keys.RandWords(24)
		require.NotEqual(t, p1, p2)
	}
}

func TestRandUsername(t *testing.T) {
	for i := 0; i < 100; i++ {
		u := keys.RandUsername(8)
		require.Equal(t, 8, len(u))
	}
}

func TestRandTempPath(t *testing.T) {
	p := keys.RandTempPath()
	require.NotEmpty(t, p)
	p2 := keys.RandTempPath()
	require.NotEqual(t, p, p2)
}
