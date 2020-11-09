package dstore_test

import (
	"context"
	"fmt"
	"log"

	"github.com/keys-pub/keys/dstore"
)

func ExampleDocuments_DocumentIterator() {
	d := dstore.NewMem()

	if err := d.Set(context.TODO(), dstore.Path("tests", 1), dstore.Data([]byte("testdata"))); err != nil {
		log.Fatal(err)
	}

	iter, err := d.DocumentIterator(context.TODO(), dstore.Path("tests"))
	if err != nil {
		log.Fatal(err)
	}
	defer iter.Release()
	for {
		doc, err := iter.Next()
		if err != nil {
			log.Fatal(err)
		}
		if doc == nil {
			break
		}
		fmt.Printf("%s: %s\n", doc.Path, string(doc.Data()))

	}

	// Output:
	// /tests/1: testdata
}
