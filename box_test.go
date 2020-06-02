package keys_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
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

func TestBox(t *testing.T) {
	ka := keys.Bytes32(encoding.MustHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	kb := keys.Bytes32(encoding.MustHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	nonce := keys.Bytes24(encoding.MustHex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"))
	plain := encoding.MustHex("be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc" +
		"e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31" +
		"0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde" +
		"048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864" +
		"5e0705")
	cipher := encoding.MustHex("f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce" +
		"48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972" +
		"71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae" +
		"90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3" +
		"7973f622a43d14a6599b1f654cb45a74e355a5")

	alice := keys.NewX25519KeyFromPrivateKey(ka)
	bob := keys.NewX25519KeyFromPrivateKey(kb)

	encrypted := alice.Seal(plain, nonce, bob.PublicKey())
	require.Equal(t, cipher, encrypted)
}
