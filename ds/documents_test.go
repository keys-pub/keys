package ds_test

import (
	"context"
	"fmt"
	"log"

	"github.com/keys-pub/keys/ds"
)

func ExampleDocumentStore_Documents() {
	d := ds.NewMem()

	if err := d.Set(context.TODO(), ds.Path("tests", 1), []byte("testdata")); err != nil {
		log.Fatal(err)
	}

	iter, err := d.Documents(context.TODO(), ds.Path("tests"), ds.NoData())
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
		fmt.Printf("%s: %s\n", doc.Path, string(doc.Data))

	}

	// Output:
	// /tests/1: testdata
}
