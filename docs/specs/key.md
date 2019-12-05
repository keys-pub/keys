# Key

A [keys.Key](https://godoc.org/github.com/keys-pub/keys#Key) is a key capable of signing and encryption.

The key is generated from a 32 byte seed. This seed is used to derive keys that are capable of signing and encryption.
This seed is all that is required to recover a key.

A key has a signing key (Ed25519, for nacl.sign), an assymetric encryption key (Curve25519 DH, for nacl.box) and a
symmetric encryption key (XSalsa20/Poly1305, for nacl.secretbox).

This key is derived in the same way as a [Keybase Per-User Key (PUK)](https://keybase.io/docs/teams/puk), using HMAC-SHA256(seed, description).

| Interface     | Description                                                                                                                                                                                                  |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ID()`        | Key identifier. It is the base58 encoded sign public key bytes.                                                                                                                                              |
| `SignKey()`   | Ed25519 (EdDSA) sign key (for use with [nacl.sign](https://godoc.org/golang.org/x/crypto/nacl/sign)). `HMAC-SHA256(seed, "Derived-User-NaCl-EdDSA-1")` as the seed for an Ed25519 signing key.               |
| `BoxKey()`    | Curve25519 DH encryption key (for use with [nacl.box](https://godoc.org/golang.org/x/crypto/nacl/box)). `HMAC-SHA256(seed, "Derived-User-NaCl-DH-1")` as the private key for a Curve25519 DH encryption key. |
| `SecretKey()` | Symmetric encryption key (for use with [nacl.secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox)). `HMAC-SHA256(seed, "Derived-User-NaCl-SecretBox-1")` as the key.                             |
| `Seed()`      | The 32 byte seed used to generate the key.                                                                                                                                                                   |
| `PublicKey()` | The public key parts.                                                                                                                                                                                        |

## PublicKey

The [keys.PublicKey](https://godoc.org/github.com/keys-pub/keys#PublicKey) is the _public_ part of a [keys.Key](https://godoc.org/github.com/keys-pub/keys#Key).

| Interface         | Description                                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------------------------- |
| `ID()`            | Key identifier, same as Key.ID(). It is the base58 encoded sign public key bytes.                              |
| `SignPublicKey()` | Ed25519 (EdDSA) sign public key (for use with [nacl.sign](https://godoc.org/golang.org/x/crypto/nacl/sign)).   |
| `BoxPublicKey()`  | Curve25519 DH encryption public key (for use with [nacl.box](https://godoc.org/golang.org/x/crypto/nacl/box)). |
| `Users()`         | User statements signed into the sigchain.                                                                      |

## Sigchain == PublicKey

Every `Key` has a corresponding [Sigchain](sigchain.md), where signed statements can be saved, and this is where we sign
public (encryption) keys and any user statements.

The [keys.Sigchain](https://godoc.org/github.com/keys-pub/keys#Sigchain) implements the PublicKey interface.

## Examples

### Generate

```go
package main

import (
    "fmt"
    "log"

    "github.com/keys-pub/keys"
)

func main() {
    alice := keys.GenerateKey()
    fmt.Printf("ID: %s\n", alice.ID())
    fmt.Printf("Seed phrase: %s\n", keys.SeedPhrase(alice))
}
```

Outputs:

```text
ID: CiHWhrK41S4vgLXwk7LvUywotS1teuDbXS9vBjADhW9C
Seed phrase: route public hire uncle glare letter kite ordinary benefit cup nerve brisk praise tiny edit summer write fatal album misery lizard law demise decrease
```

### Sign/Verify

A key can be used to sign, and the public key to verify.

```go
package main

import (
    "fmt"
    "log"

    "github.com/keys-pub/keys"
)

func main() {
    alice := keys.GenerateKey().SignKey()
    msg := "I'm alice 🤓"
    sig := keys.Sign([]byte(msg), alice)
    out, err := keys.Verify(sig, alice.PublicKey)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%s\n", string(out))
}
```

[Playground](https://play.golang.org/p/alrfZyeMIJ7)

Outputs:

```text
I'm alice 🤓
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
    alice := keys.GenerateKey().BoxKey()
    bob := keys.GenerateKey().BoxKey()

    msg := "Hey bob, it's alice. The passcode is 12345."
    encrypted := keys.BoxSeal([]byte(msg), bob.PublicKey, alice)

    out, err := keys.BoxOpen(encrypted, alice.PublicKey, bob)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("%s\n", string(out))
}
```

[Playground](https://play.golang.org/p/kDXiWVhVmJ3)

Outputs:

```text
Hey bob, it's alice. The passcode is 12345.
```
