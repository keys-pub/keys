package keys_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestBoxSeal(t *testing.T) {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	msg := "Hey bob, it's alice. The passcode is 12345."
	encrypted := keys.BoxSeal([]byte(msg), bob.PublicKey(), alice)

	out, err := keys.BoxOpen(encrypted, alice.PublicKey(), bob)
	require.NoError(t, err)
	require.Equal(t, "Hey bob, it's alice. The passcode is 12345.", string(out))
}

func ExampleBoxSeal() {
	ak := keys.GenerateX25519Key()
	bk := keys.GenerateX25519Key()

	msg := "Hey bob, it's alice. The passcode is 12345."
	encrypted := keys.BoxSeal([]byte(msg), bk.PublicKey(), ak)

	out, err := keys.BoxOpen(encrypted, ak.PublicKey(), bk)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", string(out))
	// Output:
	// Hey bob, it's alice. The passcode is 12345.
}
