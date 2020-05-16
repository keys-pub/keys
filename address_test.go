package keys_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestAddress(t *testing.T) {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01)).ID()
	bob := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x02}, 32))).ID()
	charlie := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x03}, 32))).ID()

	aliceBob, err := keys.NewAddress(alice, bob)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s:%s", alice, bob), aliceBob.String())
	bobAlice, err := keys.NewAddress(bob, alice)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s:%s", alice, bob), bobAlice.String())

	addr, err := keys.ParseAddress(fmt.Sprintf("%s:%s", alice, bob))
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s:%s", alice, bob), addr.String())

	addr2, err := keys.ParseAddress(fmt.Sprintf("%s:%s:%s", alice, bob, charlie))
	require.NoError(t, err)
	require.Equal(t, 3, len(addr2.Strings()))
	require.Equal(t, fmt.Sprintf("%s:%s:%s", alice, charlie, bob), addr2.String())

	empty, err := keys.NewAddress()
	require.EqualError(t, err, "no ids")
	require.Nil(t, empty)

	dupe, err := keys.NewAddress(alice, alice)
	require.EqualError(t, err, fmt.Sprintf("duplicate address %s", alice))
	require.Nil(t, dupe)

}
