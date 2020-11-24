package keys

import (
	"strings"

	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

// Encoding is the type of data.
type Encoding string

const (
	// UnknownEncoding is unknown.
	UnknownEncoding Encoding = ""

	// IDEncoding is a key ID string.
	IDEncoding Encoding = "id"

	// SaltpackEncoding is armored saltpack encoding.
	SaltpackEncoding Encoding = "saltpack"
	// SaltpackBinaryEncoding is binary saltpack encoding.
	// SaltpackBinaryEncoding Encoding = "saltpack-binary"

	// SSHEncoding is ssh private key "-----BEGIN OPENSSH PRIVATE..."
	// or public key as "ssh-ed25519 AAAAC3Nz..."
	SSHEncoding Encoding = "ssh"
)

// EncodeKey encodes the key using the specified encoding.
func EncodeKey(key Key, enc Encoding, password string) (string, error) {
	switch enc {
	case SaltpackEncoding:
		return EncodeSaltpackKey(key, password)
	case SSHEncoding:
		return EncodeSSHKey(key, password)
	default:
		return "", errors.Errorf("unrecognized encoding %s", enc)
	}
}

// DecodeKey decodes a key using the specified encoding.
// If you don't know the encoding you can try ParseKey instead.
func DecodeKey(s string, enc Encoding, password string) (Key, error) {
	if s == "" {
		return nil, errors.Errorf("failed to decode %s key: empty string", enc)
	}
	switch enc {
	case SaltpackEncoding:
		return DecodeSaltpackKey(s, password, false)
	case SSHEncoding:
		if strings.HasPrefix(s, "ssh-ed25519 ") {
			if password != "" {
				return nil, errors.Errorf("password unsupported for ssh-ed25519 public key")
			}
			return ParseSSHPublicKey(s)
		}
		return ParseSSHKey([]byte(s), []byte(password), true)
	default:
		return nil, errors.Errorf("unsupported encoding %s", enc)
	}
}

// EncodeSSHKey encodes key to SSH.
func EncodeSSHKey(key Key, password string) (string, error) {
	switch k := key.(type) {
	case *EdX25519Key:
		out, err := k.EncodeToSSH([]byte(password))
		if err != nil {
			return "", err
		}
		return string(out), nil
	case *EdX25519PublicKey:
		if password != "" {
			return "", errors.Errorf("password not supported when exporting public key")
		}
		return string(k.EncodeToSSHAuthorized()), nil
	default:
		return "", errors.Errorf("unsupported key type")
	}
}

// DecodeSSHKey decodes SSH key.
func DecodeSSHKey(s string, password string) (Key, error) {
	return DecodeKey(s, SSHEncoding, password)
}

// Brand is saltpack brand.
type Brand string

// EdX25519Brand is saltpack brand for EdX25519 key.
const EdX25519Brand Brand = "EDX25519 KEY"

// X25519Brand is saltpack brand for X25519 key.
const X25519Brand Brand = "X25519 KEY"

// EncodeSaltpackKey encrypts a key to saltpack with password.
func EncodeSaltpackKey(key Key, password string) (string, error) {
	if key == nil {
		return "", errors.Errorf("no key to encode")
	}
	var brand Brand
	b := key.Bytes()
	switch key.Type() {
	case EdX25519:
		brand = EdX25519Brand
	case X25519:
		brand = X25519Brand
	default:
		return "", errors.Errorf("failed to encode to saltpack: unsupported key %s", key.Type())
	}
	out := EncryptWithPassword(b, password)
	return encoding.EncodeSaltpack(out, string(brand)), nil
}

// DecodeSaltpackKey decrypts a saltpack encrypted key.
func DecodeSaltpackKey(msg string, password string, isHTML bool) (Key, error) {
	encrypted, brand, err := encoding.DecodeSaltpack(msg, isHTML)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse saltpack")
	}
	b, err := DecryptWithPassword(encrypted, password)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decrypt saltpack encoded key")
	}
	if brand == "" {
		return nil, errors.Errorf("unable to determine key type from saltpack brand")
	}
	switch brand {
	case string(EdX25519Brand):
		if len(b) != 64 {
			return nil, errors.Errorf("invalid number of bytes for ed25519 seed")
		}
		sk := NewEdX25519KeyFromPrivateKey(Bytes64(b))
		return sk, nil
	case string(X25519Brand):
		if len(b) != 32 {
			return nil, errors.Errorf("invalid number of bytes for x25519 private key")
		}
		bk := NewX25519KeyFromPrivateKey(Bytes32(b))
		return bk, nil
	default:
		return nil, errors.Errorf("unknown key type %s", brand)
	}
}
