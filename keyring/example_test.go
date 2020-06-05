package keyring_test

import (
	"fmt"
	"log"
	"time"

	"github.com/keys-pub/keys/keyring"
)

func ExampleNew() {
	// Initialize Keyring.
	// You can use keyring.System, keyring.FS, or keyring.Mem, keyring.FSV.
	kr, err := keyring.New(keyring.System("MyApp"))
	if err != nil {
		log.Fatal(err)
	}
	// Remove this Reset() if you want to keep the Keyring.
	defer func() { _ = kr.Reset() }()
	// Setup keyring auth.
	if err := kr.UnlockWithPassword("mypassword", true); err != nil {
		log.Fatal(err)
	}

	// Create item.
	// Item IDs are NOT encrypted.
	item := keyring.NewItem("id1", []byte("mysecret"), "", time.Now())
	if err := kr.Create(item); err != nil {
		log.Fatal(err)
	}

	// Get item.
	out, err := kr.Get("id1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("secret: %s\n", string(out.Data))

	// List items.
	items, err := kr.List()
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
