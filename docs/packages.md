# Packages

| Package                                                                                  | Description                                                                                                                            |
| ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| [github.com/keys-pub/keys](https://godoc.org/github.com/keys-pub/keys)                   | The core package.                                                                                                                      |
| [github.com/keys-pub/keys/keyring](https://godoc.org/github.com/keys-pub/keys/keyring)   | Secure key storage and access for any key type, implements [keys.Keyring](https://godoc.org/github.com/keys-pub/keys/keyring#Keyring). |
| [github.com/keys-pub/keys/saltpack](https://godoc.org/github.com/keys-pub/keys/saltpack) | Saltpack integration.                                                                                                                  |

While the version is less than 1.0, there may be breaking changes.

The [github.com/keys-pub/keysd](https://github.com/keys-pub/keysd) repository is for extensions and other packages using Keys.pub.

There is no guarantee of non-breaking changes here.

| Package                                                                                          | Description                                      |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------ |
| [github.com/keys-pub/keysd/service](https://godoc.org/github.com/keys-pub/keysd/service)         | Service (gRPC), and command line client.         |
| [github.com/keys-pub/keysd/http/client](https://godoc.org/github.com/keys-pub/keysd/http/client) | Client [REST API](restapi/README.md).            |
| [github.com/keys-pub/keysd/http/server](https://godoc.org/github.com/keys-pub/keysd/http/server) | Server [REST API](restapi/README.md).            |
| [github.com/keys-pub/keysd/db](https://godoc.org/github.com/keys-pub/keysd/db)                   | LevelDB implementation of keys.DocumentStore.    |
| [github.com/keys-pub/keysd/firestore](https://godoc.org/github.com/keys-pub/keysd/firestore)     | Firestore backend implements keys.DocumentStore. |
