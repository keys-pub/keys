// +build !linux

package saltpack_test

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
)

func ExampleEncryptArmored() {
	alice := keys.GenerateX25519Key()
	bob := keys.GenerateX25519Key()

	message := []byte("hi bob")

	// Encrypt from alice to bob
	encrypted, err := saltpack.EncryptArmored(message, alice, bob.ID())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d", len(encrypted))
	// Output: 375
}

func ExampleDecryptArmored() {
	// Message from ExampleEncryptArmored
	aliceID := keys.ID("kbx17jhqvdrgdyruyseuaat0rerj7ep4n63n4klufzxtzmk9p3d944gs4fg39g")
	encrypted := `BEGIN SALTPACK ENCRYPTED MESSAGE. 
	kcJn5brvybfNjz6 D5ll2Nk0YiiGFCz I2xgcLXuPzYNBe3 OboFDA8Gh0TxosH yo82IRf2OZzteqO 
	GaPWlm7t0lC0M0U vNnOvsussLf1nMw Oo1Llf9oAbA7qxa GjupUEWnTgyjjUn GKb3WvtjSgRsJS2 
	Y92GMEx8cHvbGrJ zvLGlbqAhEIDNZ2 SE15aoV6ahVxeVH 1inHyghv3H1oTAC K86mBl4fg9FY1QK 
	4n0gLOmSHbD8UYH V3HAPS0yaBC4xJB g3y04Xcqiij36Nb WmJgvSFdGugXd7O yfU.
	END SALTPACK ENCRYPTED MESSAGE.
	`

	// bobID := keys.ID("kbx18x22l7nemmxcj76f9l3aaflc5487lp5u5q778gpe3t3wzhlqvu8qxa9z07")
	b, err := hex.DecodeString("7f163f9cd538797c7c5ba5abf4f4acdfa5f52f2ffe753c40bd12f87ce279df1b")
	if err != nil {
		log.Fatal(err)
	}
	bob := keys.NewX25519KeyFromPrivateKey(keys.Bytes32(b))

	// Bob decrypts
	out, sender, err := saltpack.DecryptArmored(encrypted, bob)
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
