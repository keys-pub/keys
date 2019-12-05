# CryptoProvider

The [CryptoProvider](https://godoc.org/github.com/keys-pub/keys#CryptoProvider) interface defines how other packages
can implement signing and encryption.

| Interface (Sign/Verify)                                            |
| ------------------------------------------------------------------ |
| `Sign(b []byte, key *keys.SignKey) ([]byte, error)`                |
| `Verify(b []byte) ([]byte, keys.SignPublicKey, error)`             |
| `SignDetached(b []byte, key *keys.SignKey) ([]byte, error)`        |
| `VerifyDetached(b []byte, sig []byte) (keys.SignPublicKey, error)` |

| Interface (Seal/Open)                                                           |
| ------------------------------------------------------------------------------- |
| `Seal(b []byte, sender keys.Key, recipients ...keys.PublicKey) ([]byte, error)` |
| `Open(b []byte) ([]byte, keys.ID, error)`                                       |

## Saltpack

[Saltpack](saltpack.md) is the default CryptoProvider.

## CryptoStreamProvider

A crypto provider with stream support, also supported by [Saltpack](saltpack.md).

| Interface (Sign/Verify)                                                                |
| -------------------------------------------------------------------------------------- |
| `NewSignStream(w io.Writer, key *keys.SignKey, detached bool) (io.WriteCloser, error)` |
| `NewVerifyStream(r io.Reader) (io.Reader, keys.SignPublicKey, error)`                  |

| Interface (Seal/Open)                                                                               |
| --------------------------------------------------------------------------------------------------- |
| `NewSealStream(w io.Writer, sender keys.Key, recipients ...keys.PublicKey) (io.WriteCloser, error)` |
| `NewOpenStream(r io.Reader) (io.Reader, keys.ID, error)`                                            |
