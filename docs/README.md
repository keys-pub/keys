# keys.pub

|                                                                |                                                                                                                                                                                                              |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [github.com/keys-pub/keys](https://github.com/keys-pub/keys)   | Cryptographic key management, signing and encryption, including [keys/saltpack](https://godoc.org/github.com/keys-pub/keys/saltpack) and [keys/keyring](https://godoc.org/github.com/keys-pub/keys/keyring). |
| [github.com/keys-pub/keysd](https://github.com/keys-pub/keysd) | Service (gRPC), command line client, DB, Firestore, REST API, etc.                                                                                                                                           |
| [github.com/keys-pub/app](https://github.com/keys-pub/app)     | Desktop app (in development).                                                                                                                                                                                |

☢ This project is in development and has not been audited or reviewed. Use at your own risk. ☢

## Key

A [Key](specs/key.md) is capable of both signing and encryption. This key includes a signing key (Ed25519, for nacl.sign), an assymetric encryption key (Curve25519 DH, for nacl.box) and a symmetric encryption key (XSalsa20/Poly1305, for nacl.secretbox).

## Keystore

A [Keystore](specs/keystore.md) is a secure place to store and access keys.

## Saltpack

[Saltpack](specs/saltpack.md) is the default format used by Keys.pub and supports streaming, large message sizes, multiple recipients and armoring.

## Sigchain

A [Sigchain](specs/sigchain.md) is a chain of signed statements by a key.

## Packages

For info on repositories and packages that make Keys.pub, see [Packages](packages.md).

## REST API

A [REST API](restapi/README.md) allows you to publish user public keys and sigchain statements.
