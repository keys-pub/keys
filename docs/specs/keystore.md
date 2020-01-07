# Keystore

The [Keystore](https://godoc.org/github.com/keys-pub/keys#Keystore) is capable
of storing and retrieving key material, using identifiers.

```go
// TODO: Example
```

[Playground](https://play.golang.org/)

## Keyring

A Keystore is backed by a Keyring. In the above example, we used an in memory
keyring, which is mostly useful for testing (or for ephemeral keys).

To use a Keyring backed by the system with password auth:

```go
kr, err := keyring.NewKeyring("KeysTest", auth)
if err != nil {
    return err
}
salt, err := kr.Salt()
if err != nil {
    return err
}
auth, err := keyring.NewPasswordAuth("password123", salt)
if err != nil {
    return err
}
if err := kr.Unlock(auth); err != nil {
    return err
}
```

The [github.com/keys-pub/keys/keyring](https://godoc.org/github.com/keys-pub/keys/keyring)
package is used by the Keystore and is a secure place to persist any type
of key.
