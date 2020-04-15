package keys

import (
	"encoding/json"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

const (
	certificateItemType string = "cert-key-x509v3"
)

// NewX25519KeyItem creates keyring item for X25519Key.
func NewX25519KeyItem(key *X25519Key) *keyring.Item {
	item := keyring.NewItem(key.ID().String(), key.PrivateKey()[:], string(X25519), time.Now())
	return item
}

// AsX25519Key returns X25519Key for keyring Item.
// If item is EdX25519Key returns converted to X25519Key.
func AsX25519Key(item *keyring.Item) (*X25519Key, error) {
	switch item.Type {
	case string(X25519):
		bk := NewX25519KeyFromPrivateKey(Bytes32(item.Data))
		return bk, nil
	case string(EdX25519):
		sk, err := AsEdX25519Key(item)
		if err != nil {
			return nil, err
		}
		return sk.X25519Key(), nil
	default:
		return nil, errors.Errorf("item type %s != %s", item.Type, string(X25519))
	}
}

// NewEdX25519KeyItem creates keyring item for EdX25519Key.
func NewEdX25519KeyItem(key *EdX25519Key) *keyring.Item {
	item := keyring.NewItem(key.ID().String(), key.PrivateKey()[:], string(EdX25519), time.Now())
	return item
}

// AsEdX25519Key returns EdX25519Key for keyring Item.
func AsEdX25519Key(item *keyring.Item) (*EdX25519Key, error) {
	if item.Type != string(EdX25519) {
		return nil, errors.Errorf("item type %s != %s", item.Type, string(EdX25519))
	}
	b := item.Data
	if len(b) != 64 {
		return nil, errors.Errorf("invalid number of bytes for ed25519 private key")
	}
	key := NewEdX25519KeyFromPrivateKey(Bytes64(b))
	return key, nil
}

// NewEdX25519PublicKeyItem creates keyring item for EdX25519PublicKey.
func NewEdX25519PublicKeyItem(publicKey *EdX25519PublicKey) *keyring.Item {
	item := keyring.NewItem(publicKey.ID().String(), publicKey.Bytes()[:], string(EdX25519Public), time.Now())
	return item
}

// AsEdX25519PublicKey returns EdX25519PublicKey for keyring Item.
func AsEdX25519PublicKey(item *keyring.Item) (*EdX25519PublicKey, error) {
	switch item.Type {
	case string(EdX25519Public):
		b := item.Data
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 public key")
		}
		key := NewEdX25519PublicKey(Bytes32(b))
		return key, nil
	case string(EdX25519):
		sk, err := AsEdX25519Key(item)
		if err != nil {
			return nil, err
		}
		return sk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for sign public key: %s", item.Type)
	}
}

// NewX25519PublicKeyItem creates keyring item for X25519PublicKey.
func NewX25519PublicKeyItem(publicKey *X25519PublicKey) *keyring.Item {
	item := keyring.NewItem(publicKey.ID().String(), publicKey.Bytes()[:], string(X25519Public), time.Now())
	return item
}

// AsX25519PublicKey returns X25519PublicKey for keyring Item.
func AsX25519PublicKey(item *keyring.Item) (*X25519PublicKey, error) {
	switch item.Type {
	case string(X25519Public):
		b := item.Data
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for x25519 public key")
		}
		key := NewX25519PublicKey(Bytes32(b))
		return key, nil
	case string(X25519):
		bk, err := AsX25519Key(item)
		if err != nil {
			return nil, err
		}
		return bk.PublicKey(), nil
	default:
		return nil, errors.Errorf("invalid item type for box public key: %s", item.Type)
	}
}

type certFormat struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

// NewCertificateKeyItem creates an Item for a certificate private key.
func NewCertificateKeyItem(id string, certKey *CertificateKey) *keyring.Item {
	b, err := json.Marshal(certFormat{Private: certKey.private, Public: certKey.public})
	if err != nil {
		panic(err)
	}
	item := keyring.NewItem(id, b, certificateItemType, time.Now())
	return item
}

// AsCertificateKey returns CertificateKey for keyring Item.
func AsCertificateKey(item *keyring.Item) (*CertificateKey, error) {
	if item.Type != certificateItemType {
		return nil, errors.Errorf("item type %s != %s", item.Type, certificateItemType)
	}
	var cert certFormat
	if err := json.Unmarshal(item.Data, &cert); err != nil {
		return nil, err
	}
	return NewCertificateKey(cert.Private, cert.Public)
}
