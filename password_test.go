package keys_test

import (
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/stretchr/testify/require"
)

func TestRandPassword(t *testing.T) {
	var pass string

	pass = keys.RandPassword(1)
	require.Equal(t, 1, len(pass))

	pass = keys.RandPassword(16)
	require.Equal(t, 16, len(pass))

	set := dstore.NewStringSet()
	for i := 0; i < 1000; i++ {
		check := keys.RandPassword(8)
		require.Equal(t, 8, len(check))
		require.False(t, set.Contains(check))
		set.Add(check)
	}

	pass = keys.RandPassword(128)
	require.Equal(t, 128, len(pass))

	pass = keys.RandPassword(4096)
	require.Equal(t, 4096, len(pass))
}

func ExampleRandPassword() {
	pw := keys.RandPassword(16)
	log.Println(pw)

	pwNoSymbols := keys.RandPassword(16, keys.NoSymbols())
	log.Println(pwNoSymbols)

	// Output:
}
