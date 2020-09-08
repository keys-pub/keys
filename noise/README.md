# Noise

The [noise package](https://github.com/keys-pub/keys/blob/master/noise) helps setup a Noise handshake using X25519 keys.

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

See [noiseprotocol.org](http://www.noiseprotocol.org) for more info.

## Examples

- [Handshake + Encrypt/Decrypt](https://github.com/keys-pub/keys/blob/master/noise/example_test.go)
