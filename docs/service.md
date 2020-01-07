# Service Architecture

Keys.pub runs as a service (keysd) exposed via gRPC. It includes a command line client (keys) which connects to a locally
running service.

Access to the service is over HTTPS on 127.0.0.1 on port 10001 and is restricted to clients that are authorized (via an
auth token).

The service is designed to allow access only to explicitly authorized clients and protects key material and
cryptographic operations by using platform keychain/credentials/keyring APIs. The command line client authorizes via
`keys auth` which uses the gRPC calls AuthSetup or AuthUnlock.

For Windows and Linux, the underlying keyring is only secure at the user account level. All keyring items (except the
salt value) are encrypted, using a password/salt derived key. This provides an important additional step of protecting
keyring items on these platforms.

## macOS

The keyring is managed by the Keychain API via the [github.com/keybase/go-keychain](https://github.com/keybase/go-keychain) package.

## Windows

Keys are managed by via the Windows Credential Manager API via the [github.com/danieljoos/wincred](https://github.com/danieljoos/wincred) package.

## Linux

Keys are managed by the the Secret Service dbus interface via the [github.com/zalando/go-keyring](github.com/zalando/go-keyring)
package which depends on the Secret Service dbus interface, which is provided by GNOME Keyring.

## FS

There is a filesystem based keyring for other OS types that have no underlying keyring.
