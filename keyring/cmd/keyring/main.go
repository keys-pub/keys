package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/keys-pub/keys/keyring"
)

func main() {
	appName := flag.String("app", "Keys.keyring", "App name")
	flag.Parse()

	kr, err := keyring.New(keyring.System(*appName))
	if err != nil {
		log.Fatal(err)
	}

	ids, err := kr.IDs(keyring.Reserved())
	if err != nil {
		log.Fatal(err)
	}
	for _, id := range ids {
		fmt.Println(id)
	}
}
