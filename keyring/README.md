# Keyring

Securely store secrets.

This package provides a cross platform keyring using system APIs (macOS/keychain,
Windows/wincred, Linux/libsecret) or filesystem, encrypted by a password or
FIDO2 hmac-secret key.

For more details visit **[keys.pub](https://keys.pub)**.

## Example

```go
// Initialize Keyring.
// You can use keyring.System, keyring.FS, or keyring.Mem.
dir := env.MustAppPath(env.Dir("MyApp", "keyring"))
kr, err := keyring.New(keyring.FS(dir, true))
if err != nil {
    log.Fatal(err)
}

// Setup keyring auth.
if err := kr.UnlockWithPassword("mypassword", true); err != nil {
    log.Fatal(err)
}

// Create item.
// Item IDs are NOT encrypted.
item := keyring.NewItem("id1", []byte("mysecret"), "", time.Now())
if err := kr.Create(item); err != nil {
    log.Fatal(err)
}

// Get item.
out, err := kr.Get("id1")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("secret: %s\n", string(out.Data))

// List items.
items, err := kr.List()
if err != nil {
    log.Fatal(err)
}
for _, item := range items {
    fmt.Printf("%s: %v\n", item.ID, string(item.Data))
}
```

## macOS

The Keychain API via the [github.com/keybase/go-keychain](https://github.com/keybase/go-keychain) package.

## Windows

The Windows Credential Manager API via the [github.com/danieljoos/wincred](https://github.com/danieljoos/wincred) package.

## Linux

The SecretService dbus interface via the [github.com/zalando/go-keyring](github.com/zalando/go-keyring)
package. The SecretService dbus interface, which is provided by GNOME Keyring.

We are still exploring whether to use kwallet or libsecret directly for linux environments that support that instead.
In the meantime, you can fall back to the FS based keyring.

## FS

There is a filesystem based keyring, with a "versioned" option which can be used
to backup/sync to a remote bucket, git, etc.

## Mem

The is an in memory keyring for ephemeral keys or for testing.
