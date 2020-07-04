package docs_test

import (
	"context"
	"fmt"
	"log"

	"github.com/keys-pub/keys/docs"
)

func ExampleDocuments_DocumentIterator() {
	d := docs.NewMem()

	if err := d.Set(context.TODO(), docs.Path("tests", 1), []byte("testdata")); err != nil {
		log.Fatal(err)
	}

	iter, err := d.DocumentIterator(context.TODO(), docs.Path("tests"), docs.NoData())
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
