# Saltpack

This package allows you to encrypt/decrypt and sign/verify using Saltpack and
EdX25519 keys.

For more details visit **[keys.pub](https://keys.pub)**.

## Encrypt

The following example describes how to:

- Generate an EdX25519 key
- Encrypt to recipients (Alice and Bob) using Saltpack

```go
import (
    "github.com/keys-pub/keys"
    "github.com/keys-pub/keys/saltpack"
)

...
// Alice
alice := keys.GenerateEdX25519Key()

// Bob
bobID := keys.ID("kex1yy7amjzd5ld3k0uphvyetlz2vd8yy3fky64dut9jdf9qh852f0nsxjgv0m")

message := []byte("hi bob")

// Encrypt using Saltpack from alice to bob (include alice as a recipient too).
sp := saltpack.New(nil)
encrypted, err := sp.EncryptArmored(message, alice.X25519Key(), bobID, alice.ID())
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Encrypted: %s\n", string(encrypted))
```

## Decrypt

The following example decrypts the message from the Encrypt example:

- Initialize and setup/unlock a Keyring
- Create a Store
- Import a EdX25519 key
- Decrypt and verify a Saltpack message

```go
import (
    "github.com/keys-pub/keys"
    "github.com/keys-pub/keys/keyring"
    "github.com/keys-pub/keys/saltpack"
)

...

// Message from Alice
aliceID := keys.ID("kex1vrpxw9rqmf49kygc7ujjrdlx8lkzaarjc3s24j73xlqxhwvsyx2sw06r82")
encrypted := `BEGIN SALTPACK ENCRYPTED MESSAGE.
kcJn5brvybfNjz6 D5ll2Nk0YusOJBf 9x1CB6V3o7cdMOV ZPenXvEVhLpMBj0 8rJiM2GJTyXbhDn
cGIoczvWtRoxL5r 3EIPrfVqpwhLDke LfCV6YykdYdGwY1 lUfrzkOIUGdeURb HDSwgrTSrcexwj3
ix9Mw1FVXQGBwBV yil8lLyD1q0VFGv KmgJYyARppqQEIF HgAsZq0BJL6Dosz WGrFalmG90QA6PO
avDlwRXMDbjKFvE wQtaBDKXVSBaM9k 0Xu0CfdGUkEICbN vZNV67cGqEz2IiH kr8.
END SALTPACK ENCRYPTED MESSAGE.`

// Bob creates a Keyring and Store
kr, err := keyring.New("BobKeyring")
if err != nil {
    log.Fatal(err)
}
if err := kr.UnlockWithPassword("bobpassword", true); err != nil {
    log.Fatal(err)
}
ks := keys.NewStore(kr)

// Import edx25519 key to bob's Store
kmsg := `BEGIN EDX25519 KEY MESSAGE.
E9zL57KzBY1CIdJ d5tlpnyCIX8R5DB oLswy2g17kbfK4s CwryRUoII3ZNk3l
scLQrPmgNuKi9OK 7ugGoVWBY2n5xbK 7w500Vp2iXo6LAe XZiB06UjUdCoYJv
YjKbul2B61uxTZc waeBgRV91RZoKCn xLQnRhLXE2KC.
END EDX25519 KEY MESSAGE.`
bob, err := keys.DecodeKeyFromSaltpack(kmsg, "password", false)
if err != nil {
    log.Fatal(err)
}
if err := ks.SaveKey(bob); err != nil {
    log.Fatal(err)
}

// Bob decrypts the saltpack message.
sp := saltpack.New(ks)
out, sender, err := sp.DecryptArmored(encrypted)
if err != nil {
    log.Fatal(err)
}

// The sender from Saltpack Decrypt is a X25519 public key, so find the
// corresponding EdX25519 public key.
if sender != nil {
    pk, err := ks.FindEdX25519PublicKey(sender.ID())
    if err != nil {
        log.Fatal(err)
    }
    if pk != nil && pk.ID() == aliceID {
        fmt.Printf("signer is alice\n")
    }
}

fmt.Printf("%s\n", string(out))
```

## Sign

Sign bytes to an armored saltpack message.

```go
import (
    "github.com/keys-pub/keys"
    "github.com/keys-pub/keys/saltpack"
)
...

sp := saltpack.New(nil)

alice := keys.GenerateEdX25519Key()

message := []byte("hi from alice")

sig, err := sp.SignArmored(message, alice)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("%s\n", alice.ID())
fmt.Printf("%s\n", sig)
```

## Verify

Verify a signed saltpack message.

```go
import (
    "github.com/keys-pub/keys"
    "github.com/keys-pub/keys/saltpack"
)
...

sp := saltpack.New(nil)

aliceID := keys.ID("kex1w2jep8dkr2s0g9kx5g6xe3387jslnlj08yactvn8xdtrx4cnypjq9rpnux")
signed := `BEGIN SALTPACK SIGNED MESSAGE.
kXR7VktZdyH7rvq v5wcIkHbs7mPCSd NhKLR9E0K47y29T QkuYinHym6EfZwL
1TwgxI3RQ52fHg5 1FzmLOMghcYLcV7 i0l0ovabGhxGrEl z7WuI4O3xMU5saq
U28RqUnKNroATPO 5rn2YyQcut2SeMn lXJBlDqRv9WyxjG M0PcKvsAsvmid1m
cqA4TCjz5V9VpuO zuIQ55lRQLeP5kU aWFxq5Nl8WsPqlR RdX86OuTbaKUvKI
wdNd6ISacrT0I82 qZ71sc7sTxiMxoI P43uCGaAZZ3Ab62 vR8N6WQPE8.
END SALTPACK SIGNED MESSAGE.`

out, signer, err := sp.VerifyArmored(signed)
if err != nil {
    log.Fatal(err)
}
if signer == aliceID {
    fmt.Printf("signer is alice\n")
}
fmt.Printf("%s\n", string(out))
// Output:
// signer is alice
// hi from alice
```
