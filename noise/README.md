# Noise

This package helps setup a Noise handshake using X25519 keys.

For more details visit **[keys.pub](https://keys.pub)**.

The default cipher suite used is:
Curve25519 ECDH, ChaCha20-Poly1305 AEAD, BLAKE2b hash.

The handshake uses the KK pattern:

- K = Static key for initiator Known to responder
- K = Static key for responder Known to initiator

One of the Noise participants should be the initiator.

The order of the handshake writes/reads should be:

- (1) Initiator: Write
- (2) Responder: Read
- (3) Initiator: Read
- (4) Responder: Write

When the handshake is complete, use the Cipher to Encrypt/Decrypt.

See [noisprotocol.org](http://www.noiseprotocol.org) for more info.

The following example completes a handshake using two X25519 keys (Alice and Bob), and
uses the cipher to encrypt and decrypt.

```go
import (
    "github.com/keys-pub/keys"
    "github.com/keys-pub/keys/noise"
)

...

alice := keys.GenerateX25519Key()
bob := keys.GenerateX25519Key()

na, err := noise.NewHandshake(alice, bob.PublicKey(), true)
if err != nil {
    log.Fatal(err)
}

nb, err := noise.NewHandshake(bob, alice.PublicKey(), false)
if err != nil {
    log.Fatal(err)
}

// -> s
// <- s
ha, err := na.Write(nil)
if err != nil {
    log.Fatal(err)
}
if _, err := nb.Read(ha); err != nil {
    log.Fatal(err)
}
// -> e, es, ss
// <- e, ee, se
hb, err := nb.Write(nil)
if err != nil {
    log.Fatal(err)
}
if _, err := na.Read(hb); err != nil {
    log.Fatal(err)
}

// transport I -> R
ca, err := na.Cipher()
if err != nil {
    log.Fatal(err)
}
encrypted, err := ca.Encrypt(nil, nil, []byte("hello"))
if err != nil {
    log.Fatal(err)
}

cb, err := nb.Cipher()
if err != nil {
    log.Fatal(err)
}
decrypted, err := cb.Decrypt(nil, nil, encrypted)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("%s", string(decrypted))
// Output: hello
```
