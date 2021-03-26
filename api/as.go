package api

import "github.com/keys-pub/keys"

// As returns key as concrete type.
func (k *Key) As() keys.Key {
	if k.Private == nil {
		return k.AsPublic()
	}
	switch k.Type {
	case string(keys.EdX25519):
		return k.AsEdX25519()
	case string(keys.X25519):
		return k.AsX25519()
	case string(keys.RSA):
		return k.AsRSA()
	default:
		return nil
	}
}

// AsPublic returns public key as concrete type.
func (k *Key) AsPublic() keys.Key {
	switch k.Type {
	case string(keys.EdX25519):
		return k.AsEdX25519Public()
	case string(keys.X25519):
		return k.AsX25519Public()
	case string(keys.RSA):
		return k.AsRSAPublic()
	default:
		return nil
	}
}

// AsEdX25519 returns a *EdX25519Key.
// Returns nil if we can't resolve.
func (k *Key) AsEdX25519() *keys.EdX25519Key {
	if k.Type != string(keys.EdX25519) {
		return nil
	}
	if k.Private == nil {
		return nil
	}
	b := k.Private
	if len(b) != 64 {
		return nil
	}
	out := keys.NewEdX25519KeyFromPrivateKey(keys.Bytes64(b))
	if out.ID() != k.ID {
		return nil
	}
	return out
}

// IsEdX25519 returns true if EdX25519Key.
func (k *Key) IsEdX25519() bool {
	return k.Type == string(keys.EdX25519)
}

// AsX25519 returns a X25519Key.
// If key is a EdX25519Key, it's converted to a X25519Key.
// Returns nil if we can't resolve.
func (k *Key) AsX25519() *keys.X25519Key {
	if k.Private == nil {
		return nil
	}
	switch k.Type {
	case string(keys.X25519):
		bk := keys.NewX25519KeyFromPrivateKey(keys.Bytes32(k.Private))
		return bk
	case string(keys.EdX25519):
		sk := k.AsEdX25519()
		if sk == nil {
			return nil
		}
		return sk.X25519Key()
	default:
		return nil
	}
}

// IsEdX25519 returns true if EdX25519Key.
func (k *Key) IsX25519() bool {
	return k.Type == string(keys.X25519)
}

// AsEdX25519Public returns a *EdX25519PublicKey.
// Returns nil if we can't resolve.
func (k *Key) AsEdX25519Public() *keys.EdX25519PublicKey {
	if k.Type != string(keys.EdX25519) {
		return nil
	}

	if k.Private == nil {
		b := k.Public
		if len(b) != 32 {
			return nil
		}
		out := keys.NewEdX25519PublicKey(keys.Bytes32(b))
		return out
	}

	sk := k.AsEdX25519()
	if sk == nil {
		return nil
	}
	return sk.PublicKey()
}

// AsX25519Public returns a X25519PublicKey.
// Returns nil if we can't resolve.
func (k *Key) AsX25519Public() *keys.X25519PublicKey {
	switch k.Type {
	case string(keys.X25519):
		b := k.Public
		if len(b) != 32 {
			return nil
		}
		return keys.NewX25519PublicKey(keys.Bytes32(b))
	case string(keys.EdX25519):
		return k.AsEdX25519Public().X25519PublicKey()
	default:
		return nil
	}
}

// AsRSA returns a RSAKey.
// Returns nil if we can't resolve.
func (k *Key) AsRSA() *keys.RSAKey {
	if k.Private == nil {
		return nil
	}
	if k.Type != string(keys.RSA) {
		return nil
	}
	rk, err := keys.NewRSAKeyFromBytes(k.Private)
	if err != nil {
		return nil
	}
	return rk
}

// AsRSAPublic returns a RSAPublicKey.
// Returns nil if we can't resolve.
func (k *Key) AsRSAPublic() *keys.RSAPublicKey {
	if k.Type != string(keys.RSA) {
		return nil
	}
	pk, err := keys.NewRSAPublicKeyFromBytes(k.Public)
	if err != nil {
		return nil
	}
	return pk
}
