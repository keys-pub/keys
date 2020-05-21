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

	kr, err := keyring.New(*appName, keyring.System())
	if err != nil {
		log.Fatal(err)
	}

	opts := &keyring.options.IDs{ShowHidden: true, ShowReserved: true}

	ids, err := kr.IDs(opts)
	if err != nil {
		log.Fatal(err)
	}
	for _, id := range ids {
		fmt.Println(id)
	}
}
