package saltpack_test

import (
	"fmt"
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
)

func ExampleSigncrypt() {
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bobID := keys.ID("kex1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2quf6zcg")

	message := []byte("hi bob")

	fmt.Printf("alice: %s\n", alice.ID())
	fmt.Printf("bob: %s\n", bobID)

	// Signcrypt from alice to bob
	encrypted, err := saltpack.Signcrypt(message, true, alice, bobID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s...\n", encrypted[0:30])
	// Output:
	// alice: kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077
	// bob: kex1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2quf6zcg
	// BEGIN SALTPACK ENCRYPTED MESSA...
}

func ExampleSigncryptOpen() {
	aliceID := keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077")
	encrypted := []byte(`BEGIN SALTPACK ENCRYPTED MESSAGE. 
	keDIDMQWYvVR58B FTfTeDQNHw4rtf4 DhnUhh7QIMs1BwB LmssBxGhQ4mlcCU qV8WjYl8IkxQJbg 
	ONicYJ6bKt4MtL5 u1uoXQQMHpGQoxv i81G0YjJmVk3fve kTnkT7hxuNZPhL3 2gdI2jzdhgOuv2I 
	GepiKbfYFkh9crE 1N4kuPgLFmiQoUb UxbqPeFjmNwUTf7 zGeNEy8DBW16Iyd jw64NZ1Ln4gebRP 
	2mFMbPdyBRdxldx ugMs9cTZ2cTcyWJ mTPQ9RkdnnfPGdd k6x2hQWAdkwBOmy 4NcS7hFls2iGX4I 
	4lh5nDtDzwGHFOn ehwbipT7iNVK9kE 388GznWBW4Vci88 43Z1Txd2cbm2dBJ y883ohi7SLL. 
	END SALTPACK ENCRYPTED MESSAGE.`)

	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	// Bob decrypts
	out, sender, err := saltpack.SigncryptOpen(encrypted, true, saltpack.NewKeyring(bob))
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
