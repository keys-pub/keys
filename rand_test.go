package keys

import (
	"bytes"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandID(t *testing.T) {
	kid := RandID("test")
	require.False(t, strings.Contains(kid.String(), "="))
}

func TestRandBytes(t *testing.T) {
	b1 := RandBytes(32)
	require.Equal(t, 32, len(b1))
	for i := 0; i < 1000; i++ {
		b2 := RandBytes(32)
		require.False(t, bytes.Equal(b1, b2))
	}
}

func TestRandWords(t *testing.T) {
	p6 := RandWords(6)
	require.Equal(t, 6, len(strings.Split(p6, " ")))
	require.Panics(t, func() { RandWords(0) })

	p1 := RandWords(24)
	require.Equal(t, 24, len(strings.Split(p1, " ")))
	require.Panics(t, func() { RandWords(25) })

	for i := 0; i < 1000; i++ {
		p2 := RandWords(24)
		require.NotEqual(t, p1, p2)
	}
}

func TestRandPassphrase(t *testing.T) {
	p1 := RandPassphrase(16)
	require.Equal(t, 16, len(p1))

	require.Panics(t, func() { RandPassphrase(11) })

	for i := 0; i < 1000; i++ {
		p2 := RandPassphrase(16)
		require.NotEqual(t, p1, p2)
	}

	p3 := RandPassphrase(128)
	require.Equal(t, 128, len(p3))
}

func TestRand32P4(t *testing.T) {
	rs := make([]string, 0, 100)
	for i := uint32(1); i < 100; i++ {
		b := Rand32P4(i)
		rs = append(rs, hex.EncodeToString(b[:]))
	}
	require.True(t, sort.StringsAreSorted(rs))
}

func TestRandUsername(t *testing.T) {
	for i := 0; i < 100; i++ {
		u := RandUsername(8)
		require.Equal(t, 8, len(u))
	}
}

func TestRandString(t *testing.T) {
	s := RandString(32)
	require.Equal(t, 43, len(s))
}
