# Keys

| Key       | Description                                                                                             |
| --------- | ------------------------------------------------------------------------------------------------------- |
| `SignKey` | Ed25519 (EdDSA) sign key (for use with [nacl.sign](https://godoc.org/golang.org/x/crypto/nacl/sign)).   |
| `BoxKey`  | Curve25519 DH encryption key (for use with [nacl.box](https://godoc.org/golang.org/x/crypto/nacl/box)). |

## Examples

### Generate

```go
package main

import (
    "fmt"

    "github.com/keys-pub/keys"
)

func main() {
    alice := keys.GenerateSignKey()
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
    alice := keys.GenerateSignKey()
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
    alice := keys.GenerateBoxKey()
    bob := keys.GenerateBoxKey()

    msg := "Hey bob, it's alice. The passcode is 12345."
    encrypted := keys.BoxSeal([]byte(msg), bob.PublicKey, alice)

    out, err := keys.BoxOpen(encrypted, alice.PublicKey, bob)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("%s\n", string(out))
}
```
