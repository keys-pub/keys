# Keyring

Securely store secrets.

This package provides a cross platform keyring using system APIs (macOS/keychain,
Windows/wincred, Linux/SecretService) or filesystem, protected by a password derived key.

For more details visit **[keys.pub](https://keys.pub)**.

## Example

```go
kr, err := keyring.NewKeyring("AppName", keyring.System())
if err != nil {
    log.Fatal(err)
}

// Unlock keyring (on first unlock, sets the password)
if err := keyring.UnlockWithPassword(kr, "mypassword"); err != nil {
    log.Fatal(err)
}

// Save item
item := keyring.NewItem("id1", secret, "", time.Now())
if err := kr.Create(item); err != nil {
    log.Fatal(err)
}

// Get item
out, err := kr.Get("id1")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("secret: %s\n", string(out.SecretData()))

// List items
items, err := kr.List(nil)
if err != nil {
    log.Fatal(err)
}
for _, item := range items {
    fmt.Printf("%s: %v\n", item.ID, string(item.SecretData()))
}
```

## macOS

The Keychain API via the [github.com/keybase/go-keychain](https://github.com/keybase/go-keychain) package.

## Windows

The Windows Credential Manager API via the [github.com/danieljoos/wincred](https://github.com/danieljoos/wincred) package.

## Linux

The Secret Service dbus interface via the [github.com/zalando/go-keyring](github.com/zalando/go-keyring)
package. The Secret Service dbus interface, which is provided by GNOME Keyring.

## FS

There is a filesystem based keyring for other OS types that have no system keyring.
