package saltpack_test

import (
	"fmt"
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
)

func ExampleEncrypt() {
	alice := keys.NewX25519KeyFromSeed(testSeed(0x01))
	bobID := keys.ID("kbx1e6xn45wvkce7c7msc9upffw8dmxs9959q5xng369hgzcwrjc04vs8u82mj")

	message := []byte("hi bob")

	fmt.Printf("alice: %s\n", alice.ID())
	fmt.Printf("bob: %s\n", bobID)

	// Encrypt from alice to bob
	encrypted, err := saltpack.Encrypt(message, true, alice, bobID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s...\n", encrypted[0:30])
	// Output:
	// alice: kbx15nsf9y4k28p83wth93tf7hafhvfajp45d2mge80ems45gz0c5gys57cytk
	// bob: kbx1e6xn45wvkce7c7msc9upffw8dmxs9959q5xng369hgzcwrjc04vs8u82mj
	// BEGIN SALTPACK ENCRYPTED MESSA...
}

func ExampleDecrypt() {
	aliceID := keys.ID("kbx15nsf9y4k28p83wth93tf7hafhvfajp45d2mge80ems45gz0c5gys57cytk")
	encrypted := []byte(`BEGIN SALTPACK ENCRYPTED MESSAGE. 
	kcJn5brvybfNjz6 D5ll2Nk0YnkdsxV g8EmizCg7a8zpHt Wh3GEuw5BrCUP2u N00ZdO6tTiw5NAl 
	M2M9M0ErPX1xAmK Cfh7IG2sQfbxIH3 OmQwZxc13hjpoG4 1NWwphYm2HR7i1Z LOdCpf8kbf5UFSC 
	eEUlInuYgfWLJdT 7y3iBbCvlejdmJW aSRZAgrmiEqYfTL a0NzUyir4lT4h9G DUYEGWA8JD3cuCh 
	Xfi0TNH5BlgOnBm 65o53Xaztwpv6Q4 BMM6AoTyMYk9iR3 5ybluVFI5DJq0YP N6t. 
	END SALTPACK ENCRYPTED MESSAGE.`)

	bob := keys.NewX25519KeyFromSeed(testSeed(0x02))

	// Bob decrypts
	out, sender, err := saltpack.Decrypt(encrypted, true, saltpack.NewKeyring(bob))
	if err != nil {
		log.Fatal(err)
	}

	if sender != nil && sender.ID() == aliceID {
		fmt.Printf("signer is alice\n")
	}
	fmt.Printf("%s\n", string(out))

	// Output:
	// signer is alice
	// hi bob
}
