# Saltpack

Saltpack is the default format used in Keys.pub.

It supports streaming, large message sizes, multiple recipients and armoring.

The [github.com/keys-pub/keys/saltpack](https://godoc.org/github.com/keys-pub/keys/saltpack) package
provides support for the [saltpack protocol](https://saltpack.org).

We use the [signcryption](https://saltpack.org/signcryption-format) format by default.

## Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/keys-pub/keys"
    "github.com/keys-pub/keys/keyring"
    "github.com/keys-pub/keys/saltpack"
)

func main() {
    alice := keys.GenerateKey()
    bob := keys.GenerateKey()

    // Alice's keystore, save alice's key
    ksa := keys.NewMemKeystore()
    ksa.SetKeyring(keyring.NewMem())
    if err := ksa.SaveKey(alice, false); err != nil {
      log.Fatal(err)
    }
    spa := saltpack.NewSaltpack(ksa)
    spa.SetArmored(true)
    msg := []byte("Hey bob, it's alice. The passcode is 12345.")
    // Alice encrypts
    encrypted, err := spa.Seal(msg, alice, bob.PublicKey())
    if err != nil {
      log.Fatal(err)
    }
    fmt.Println(string(encrypted))

    // Bob's keystore, save bob's key and alice's public key
    ksb := keys.NewMemKeystore()
    ksb.SetKeyring(keyring.NewMem())
    spb := saltpack.NewSaltpack(ksb)
    spb.SetArmored(true)
    if err := ksb.SaveKey(bob, false); err != nil {
        log.Fatal(err)
    }
    // Bob decrypts
    out, sender, err := spb.Open(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    if sender != alice.ID() {
        log.Fatalf("Sender not alice")
    }
    fmt.Printf("%s\n", string(out))
}
```

[Playground](https://play.golang.org/p/QvFZmgYYUlY)

```text
BEGIN SALTPACK ENCRYPTED MESSAGE. keDIDMQWYvVR58B FTfTeDQNHpkjAAR 4YgkTN8Bzl5YcxB
1f9HwKbXDg1Zno6 xQdTPtcEY3bxdE6 e3y6AoujRz7KgOq 1dcfI3ueKmnLWhx GBvwXaZjolpqobv
xeDVrJufXk63De6 G2wPriYArnB26Oc sZtal0Oh9eB9eNs Ettd4XiLwRl4k1x mA7y5rgNcz1Pehw
efmecgPCsDKMLh8 2Xgh85euHgwq0tG sW1sEkAXjYav036 0R6foRUjLxquAcn IVWojATt9UIaHwc
oiwNqK6LnDb6vQM IGr4RACAaDM4nHo RiOd2OXrIvhixjA yFRaUgvKVAvRSRG eRfawuzVqPdeAdi
mMpUxy3rAXNUDiA LZaKFk5C0aSj2O5 etLS6l7FZT3fBGx vOHJtdnPnqsm6Xe zoKyKCjb1WNf5QD
j. END SALTPACK ENCRYPTED MESSAGE.

Hey bob, it's alice. The passcode is 12345.
```
