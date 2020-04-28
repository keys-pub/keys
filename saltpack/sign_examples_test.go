package saltpack_test

import (
	"fmt"
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
)

func ExampleSaltpack_Sign() {
	sp := saltpack.NewSaltpack(nil)

	alice := keys.GenerateEdX25519Key()

	message := []byte("hi from alice")

	sig, err := sp.SignArmored(message, alice)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", alice.ID())
	fmt.Printf("%s\n", sig)
}

func ExampleSaltpack_SignDetached() {
	sp := saltpack.NewSaltpack(nil)

	alice := keys.GenerateEdX25519Key()

	message := []byte("hi from alice")

	sig, err := sp.SignArmoredDetached(message, alice)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", sig)
}

func ExampleSaltpack_Verify() {
	sp := saltpack.NewSaltpack(nil)

	aliceID := keys.ID("kex1w2jep8dkr2s0g9kx5g6xe3387jslnlj08yactvn8xdtrx4cnypjq9rpnux")
	signed := `BEGIN SALTPACK SIGNED MESSAGE. 
	kXR7VktZdyH7rvq v5wcIkHbs7mPCSd NhKLR9E0K47y29T QkuYinHym6EfZwL 
	1TwgxI3RQ52fHg5 1FzmLOMghcYLcV7 i0l0ovabGhxGrEl z7WuI4O3xMU5saq 
	U28RqUnKNroATPO 5rn2YyQcut2SeMn lXJBlDqRv9WyxjG M0PcKvsAsvmid1m 
	cqA4TCjz5V9VpuO zuIQ55lRQLeP5kU aWFxq5Nl8WsPqlR RdX86OuTbaKUvKI 
	wdNd6ISacrT0I82 qZ71sc7sTxiMxoI P43uCGaAZZ3Ab62 vR8N6WQPE8. 
	END SALTPACK SIGNED MESSAGE.`

	out, signer, err := sp.VerifyArmored(signed)
	if err != nil {
		log.Fatal(err)
	}
	if signer == aliceID {
		fmt.Printf("signer is alice\n")
	}
	fmt.Printf("%s\n", string(out))
	// Output:
	// signer is alice
	// hi from alice
}
