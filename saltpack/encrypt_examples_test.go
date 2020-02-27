// +build !linux

package saltpack_test

import (
	"fmt"
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/keys-pub/keys/saltpack"
)

func ExampleSaltpack_Encrypt() {
	sp := saltpack.NewSaltpack(nil)

	// Alice
	alice := keys.GenerateEdX25519Key()

	// Bob
	bobID := keys.ID("kex1yy7amjzd5ld3k0uphvyetlz2vd8yy3fky64dut9jdf9qh852f0nsxjgv0m")

	message := []byte("hi bob")

	// Encrypt from alice to bob
	encrypted, err := sp.EncryptArmored(message, alice.X25519Key(), bobID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d", len(encrypted))
	// Output: 375
}

func ExampleSaltpack_Decrypt() {
	// Message from Alice
	aliceID := keys.ID("kex1vrpxw9rqmf49kygc7ujjrdlx8lkzaarjc3s24j73xlqxhwvsyx2sw06r82")
	encrypted := `BEGIN SALTPACK ENCRYPTED MESSAGE. 
	kcJn5brvybfNjz6 D5ll2Nk0YusOJBf 9x1CB6V3o7cdMOV ZPenXvEVhLpMBj0 8rJiM2GJTyXbhDn 
	cGIoczvWtRoxL5r 3EIPrfVqpwhLDke LfCV6YykdYdGwY1 lUfrzkOIUGdeURb HDSwgrTSrcexwj3 
	ix9Mw1FVXQGBwBV yil8lLyD1q0VFGv KmgJYyARppqQEIF HgAsZq0BJL6Dosz WGrFalmG90QA6PO 
	avDlwRXMDbjKFvE wQtaBDKXVSBaM9k 0Xu0CfdGUkEICbN vZNV67cGqEz2IiH kr8. 
	END SALTPACK ENCRYPTED MESSAGE.`

	// Bob creates a Keyring and Keystore
	kr, err := keyring.NewKeyring("BobKeyring", keyring.System())
	if err != nil {
		log.Fatal(err)
	}
	// Remove this Reset() if you want to keep the Keyring
	defer kr.Reset()
	if err := keyring.UnlockWithPassword(kr, "bobpassword"); err != nil {
		log.Fatal(err)
	}
	ks := keys.NewKeystore(kr)
	sp := saltpack.NewSaltpack(ks)

	kmsg := `BEGIN EDX25519 KEY MESSAGE.
	E9zL57KzBY1CIdJ d5tlpnyCIX8R5DB oLswy2g17kbfK4s CwryRUoII3ZNk3l
	scLQrPmgNuKi9OK 7ugGoVWBY2n5xbK 7w500Vp2iXo6LAe XZiB06UjUdCoYJv
	YjKbul2B61uxTZc waeBgRV91RZoKCn xLQnRhLXE2KC.
	END EDX25519 KEY MESSAGE.`
	bob, err := keys.DecodeKeyFromSaltpack(kmsg, "password", false)
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.SaveKey(bob); err != nil {
		log.Fatal(err)
	}

	// Bob decrypt's
	out, signer, err := sp.DecryptArmored(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	// The signer from Saltpack Decrypt is a x25519 ID, so compare using
	// keys.PublicKeyIDEquals.
	if keys.PublicKeyIDEquals(aliceID, signer) {
		fmt.Printf("signer is alice\n")
	}
	fmt.Printf("%s\n", string(out))

	// Output:
	// signer is alice
	// hi bob
}
