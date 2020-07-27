package saltpack

import (
	"bufio"
	"io"
	"reflect"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

// Encrypt to recipients.
// Sender can be nil, if you want it to be anonymous.
// https://saltpack.org/encryption-format-v2
func Encrypt(b []byte, armored bool, sender *keys.X25519Key, recipients ...keys.ID) ([]byte, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	if armored {
		s, err := ksaltpack.EncryptArmor62Seal(ksaltpack.Version2(), b, sbk, recs, "")
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return ksaltpack.Seal(ksaltpack.Version2(), b, sbk, recs)
}

func x25519SenderKey(info *ksaltpack.MessageKeyInfo) (*keys.X25519PublicKey, error) {
	var sender *keys.X25519PublicKey
	if !info.SenderIsAnon {
		b := info.SenderKey.ToKID()
		if len(b) != 32 {
			return nil, errors.Errorf("invalid x25519 sender key")
		}
		sender = keys.NewX25519PublicKey(keys.Bytes32(b))
	}
	return sender, nil
}

// Open decrypts bytes after attempting to auto detect the encoding.
func Open(b []byte, kr Keyring) (out []byte, key keys.Key, enc Encoding, err error) {
	enc, armored := detectEncrypt(b)
	switch enc {
	case EncryptEncoding:
		out, key, err = Decrypt(b, armored, kr)
	case SigncryptEncoding:
		out, key, err = SigncryptOpen(b, armored, kr)
	default:
		err = errors.Errorf("invalid data")
	}
	if isNil(key) {
		key = nil
	}
	return
}

// Decrypt bytes.
// If there was a sender, will return the X25519 public key.
func Decrypt(b []byte, armored bool, kr Keyring) ([]byte, *keys.X25519PublicKey, error) {
	s := newSaltpack(kr)
	var info *ksaltpack.MessageKeyInfo
	var out []byte
	var err error
	if armored {
		info, out, _, err = ksaltpack.Dearmor62DecryptOpen(encryptVersionValidator, string(b), s)
	} else {
		info, out, err = ksaltpack.Open(encryptVersionValidator, b, s)
	}
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return out, sender, nil
}

// NewEncryptStream creates an encrypted armored io.WriteCloser.
// Sender can be nil, if you want it to be anonymous.
func NewEncryptStream(w io.Writer, armored bool, sender *keys.X25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	if armored {
		return ksaltpack.NewEncryptArmor62Stream(ksaltpack.Version2(), w, sbk, recs, "")
	}
	return ksaltpack.NewEncryptStream(ksaltpack.Version2(), w, sbk, recs)
}

// NewReader creates io.Reader for decryption after trying to detect the encoding.
// We peek up to 512 bytes from the reader, detect the encoding and return that stream.
func NewReader(r io.Reader, kr Keyring) (out io.Reader, key keys.Key, enc Encoding, err error) {
	buf := bufio.NewReader(r)
	var peek []byte
	peek, err = buf.Peek(512)
	if err != nil {
		if err != io.EOF {
			return
		}
	}
	enc, armored := detectEncrypt(peek)
	switch enc {
	case EncryptEncoding:
		out, key, err = NewDecryptStream(buf, armored, kr)
	case SigncryptEncoding:
		out, key, err = NewSigncryptOpenStream(buf, armored, kr)
	default:
		err = errors.Errorf("invalid data")
	}
	if isNil(key) {
		key = nil
	}
	return
}

// NewDecryptStream creates a decrypt stream.
// If there was a sender, will return a X25519 key ID.
func NewDecryptStream(r io.Reader, armored bool, kr Keyring) (io.Reader, *keys.X25519PublicKey, error) {
	s := newSaltpack(kr)

	var info *ksaltpack.MessageKeyInfo
	var stream io.Reader
	var err error
	if armored {
		info, stream, _, err = ksaltpack.NewDearmor62DecryptStream(encryptVersionValidator, r, s)
	} else {
		info, stream, err = ksaltpack.NewDecryptStream(encryptVersionValidator, r, s)
	}
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return stream, sender, nil
}

// isNil checks if a specified object is nil.
func isNil(object interface{}) bool {
	if object == nil {
		return true
	}

	value := reflect.ValueOf(object)
	kind := value.Kind()
	isNilableKind := containsKind(
		[]reflect.Kind{
			reflect.Chan, reflect.Func,
			reflect.Interface, reflect.Map,
			reflect.Ptr, reflect.Slice},
		kind)

	if isNilableKind && value.IsNil() {
		return true
	}

	return false
}

// containsKind checks if a specified kind in the slice of kinds.
func containsKind(kinds []reflect.Kind, kind reflect.Kind) bool {
	for i := 0; i < len(kinds); i++ {
		if kind == kinds[i] {
			return true
		}
	}

	return false
}
