package keyring_test

import (
	"fmt"
	"log"
	"time"

	"github.com/keys-pub/keys/keyring"
)

func ExampleNewKeyring() {
	kr, err := keyring.NewKeyring("AppName", keyring.SystemOrFS())
	if err != nil {
		log.Fatal(err)
	}
	// Remove this Reset() if you want to keep the Keyring
	defer func() { _ = kr.Reset() }()
	// Unlock keyring (on first unlock, sets the password)
	if err := keyring.UnlockWithPassword(kr, "mypassword"); err != nil {
		log.Fatal(err)
	}

	// Save secret
	item := keyring.NewItem("id1", []byte("mysecret"), "", time.Now())
	if err := kr.Create(item); err != nil {
		log.Fatal(err)
	}

	// Get secret
	out, err := kr.Get("id1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("secret: %s\n", string(out.Data))

	// List secrets
	items, err := kr.List(nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, item := range items {
		fmt.Printf("%s: %v\n", item.ID, string(item.Data))
	}

	// Output:
	// secret: mysecret
	// id1: mysecret
}
