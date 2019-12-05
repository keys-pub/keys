# DocumentStore

The [DocumentStore](https://godoc.org/github.com/keys-pub/keys#DocumentStore) interface defines a document store. We'll use to store and lookup public keys.

| Interface                                                                                      | Description                |
| ---------------------------------------------------------------------------------------------- | -------------------------- |
| `Create(ctx context.Context, path string, b []byte) error`                                     | Create document.           |
| `Set(ctx context.Context, path string, b []byte) error`                                        | Create or set document.    |
| `Get(ctx context.Context, path string) (*Document, error)`                                     | Get document.              |
| `GetAll(ctx context.Context, paths []string) ([]*Document, error)`                             | Get all documents in bulk. |
| `Exists(ctx context.Context, path string) (bool, error)`                                       | Check if exists.           |
| `Delete(ctx context.Context, path string) (bool, error)`                                       | Delete.                    |
| `Documents(ctx context.Context, parent string, opts *DocumentsOpts) (DocumentIterator, error)` | Documents.                 |
| `Collections(ctx context.Context, parent string) (CollectionIterator, error)`                  | Collections.               |

## DB

The [github.com/keys-pub/keysd/db](https://godoc.org/github.com/keys-pub/keysd/db) package is a [DocumentStore](https://godoc.org/github.com/keys-pub/keys#DocumentStore) implementation backed by Leveldb.

```go
package main

import (
    "context"
    "log"

    "github.com/keys-pub/keysd/db"
)

func main() {
    db := db.NewDB()
    defer db.Close()
    if err := db.OpenAtPath("/tmp/keys.db"); err != nil {
        log.Fatal(err)
    }

    if err := db.Create(context.TODO(), "/test/key1", []byte("value1")); err != nil {
        log.Fatal(err)
    }

    entry, err := db.Get(context.TODO(), "/test/key1")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("%+v\n", entry)
}
```

## Firestore

The [github.com/keys-pub/keysd/firestore](https://godoc.org/github.com/keys-pub/keysd/firestore) package is a [DocumentStore](https://godoc.org/github.com/keys-pub/keys#DocumentStore) implementation backed by Firestore.

```go
package main

import (
    "context"
    "log"

    "github.com/keys-pub/keysd/firestore"
    "google.golang.org/api/option"
)

func main() {
    url := "firestore://projectname"
    opts := []option.ClientOption{option.WithCredentialsFile("credentials.json")}
    fi, err := firestore.NewFirestore(url, opts...)
    if err != nil {
        log.Fatal(err)
    }

    if err := fi.Create(context.TODO(), "/test/key1", []byte("value1")); err != nil {
        log.Fatal(err)
    }

    entry, err := fi.Get(context.TODO(), "test/key1")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("%+v\n", entry)
}
```
