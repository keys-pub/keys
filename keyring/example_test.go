package keyring_test

import (
	"fmt"
	"log"
	"time"

	"github.com/keys-pub/keys/keyring"
)

func ExampleNew() {
	kr, err := keyring.New("AppName", keyring.SystemOrFS())
	if err != nil {
		log.Fatal(err)
	}
	// Remove this Reset() if you want to keep the Keyring
	defer func() { _ = kr.Reset() }()
	// Unlock keyring (on first unlock, sets the password)
	if err := kr.UnlockWithPassword("mypassword"); err != nil {
		log.Fatal(err)
	}

	// Save item
	item := keyring.NewItem("id1", []byte("mysecret"), "", time.Now())
	if err := kr.Create(item); err != nil {
		log.Fatal(err)
	}

	// Get item
	out, err := kr.Get("id1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("secret: %s\n", string(out.Data))

	// List items
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
