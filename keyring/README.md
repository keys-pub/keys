# Keyring

This package provides a cross platform keyring using system APIs (macOS/keychain,
Windows/wincred, Linux/libsecret).

For more details visit **[keys.pub](https://keys.pub)**.

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

There is a filesystem based keyring.

## Mem

The is an in memory keyring for ephemeral keys or for testing.
