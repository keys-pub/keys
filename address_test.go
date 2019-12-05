package keys

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddress(t *testing.T) {
	alice := randOID(1)
	bob := randOID(2)
	charlie := randOID(3)

	aliceBob, err := NewAddress(alice, bob)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s:%s", alice, bob), aliceBob.String())
	bobAlice, err := NewAddress(bob, alice)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s:%s", alice, bob), bobAlice.String())

	addr, err := ParseAddress(fmt.Sprintf("%s:%s", alice, bob))
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s:%s", alice, bob), addr.String())

	addr2, err := ParseAddress(fmt.Sprintf("%s:%s:%s", alice, bob, charlie))
	require.NoError(t, err)
	require.Equal(t, 3, len(addr2.Recipients()))

	empty, err := NewAddress()
	require.EqualError(t, err, "no recipients")
	require.Nil(t, empty)

	dupe, err := NewAddress(alice, alice)
	require.EqualError(t, err, fmt.Sprintf("duplicate address %s", alice))
	require.Nil(t, dupe)

}
