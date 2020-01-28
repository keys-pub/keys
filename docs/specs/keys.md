# Keys

| Key        | Description                                       |
| ---------- | ------------------------------------------------- |
| `EdX25519` | EdX25519 (Ed25519/X25519) signing/encryption key. |
| `X25519`   | X25519 encryption key.                            |

## Examples

### Generate

```go
package main

import (
    "fmt"

    "github.com/keys-pub/keys"
)

func main() {
    alice := keys.GenerateEdX25519Key()
    fmt.Printf("ID: %s\n", alice.ID())
}
```

### Sign/Verify

```go
package main

import (
    "fmt"
    "log"

    "github.com/keys-pub/keys"
)

func main() {
    alice := keys.GenerateEdX25519Key()
    msg := "I'm alice 🤓"
    sig := alice.Sign([]byte(msg))
    out, err := alice.Verify(sig)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%s\n", string(out))
}
```

### Encrypt/Decrypt

You can encrypt to a public key.

```go
package main

import (
    "fmt"
    "log"

    "github.com/keys-pub/keys"
)

func main() {
    alice := keys.GenerateX25519Key()
    bob := keys.GenerateX25519Key()

    msg := "Hey bob, it's alice. The passcode is 12345."
    encrypted := keys.BoxSeal([]byte(msg), bob.PublicKey, alice)

    out, err := keys.BoxOpen(encrypted, alice.PublicKey, bob)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("%s\n", string(out))
}
```
