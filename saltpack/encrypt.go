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
func Encrypt(b []byte, sender *keys.X25519Key, recipients ...keys.ID) ([]byte, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	return ksaltpack.Seal(ksaltpack.Version2(), b, sbk, recs)
}

// EncryptArmored encrypts to recipients (armored).
func EncryptArmored(b []byte, brand string, sender *keys.X25519Key, recipients ...keys.ID) (string, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return "", err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	s, err := ksaltpack.EncryptArmor62Seal(ksaltpack.Version2(), b, sbk, recs, brand)
	if err != nil {
		return "", err
	}
	return s, nil
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
func Open(b []byte, kr Keyring) (out []byte, key keys.Key, detected Detected, err error) {
	detected = detectEncrypt(b)
	switch detected.Encoding {
	case EncryptEncoding:
		if detected.Armored {
			var brand string
			out, key, brand, err = DecryptArmored(string(b), kr)
			detected.Brand = brand
		} else {
			out, key, err = Decrypt(b, kr)
		}
	case SigncryptEncoding:
		if detected.Armored {
			var brand string
			out, key, brand, err = SigncryptOpenArmored(string(b), kr)
			detected.Brand = brand
		} else {
			out, key, err = SigncryptOpen(b, kr)
		}
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
func Decrypt(b []byte, kr Keyring) ([]byte, *keys.X25519PublicKey, error) {
	sp := newSaltpack(kr)
	info, out, err := ksaltpack.Open(encryptVersionValidator, b, sp)
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return out, sender, nil
}

// DecryptArmored decrypts armored data.
func DecryptArmored(s string, kr Keyring) ([]byte, *keys.X25519PublicKey, string, error) {
	sp := newSaltpack(kr)
	info, out, brand, err := ksaltpack.Dearmor62DecryptOpen(encryptVersionValidator, s, sp)
	if err != nil {
		return nil, nil, "", convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, "", err
	}
	return out, sender, brand, nil
}

// NewEncryptStream creates an encrypted armored io.WriteCloser.
// Sender can be nil, if you want it to be anonymous.
func NewEncryptStream(w io.Writer, sender *keys.X25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	return ksaltpack.NewEncryptStream(ksaltpack.Version2(), w, sbk, recs)
}

// NewEncryptArmoredStream creates an encrypted armored io.WriteCloser.
// Sender can be nil, if you want it to be anonymous.
func NewEncryptArmoredStream(w io.Writer, brand string, sender *keys.X25519Key, recipients ...keys.ID) (io.WriteCloser, error) {
	recs, err := boxPublicKeys(recipients)
	if err != nil {
		return nil, err
	}
	var sbk ksaltpack.BoxSecretKey
	if sender != nil {
		sbk = newBoxKey(sender)
	}
	return ksaltpack.NewEncryptArmor62Stream(ksaltpack.Version2(), w, sbk, recs, brand)
}

// NewReader creates io.Reader for decryption after trying to detect the encoding.
// We peek up to 512 bytes from the reader, detect the encoding and return that stream.
func NewReader(r io.Reader, kr Keyring) (out io.Reader, key keys.Key, enc Encoding, armored bool, err error) {
	buf := bufio.NewReader(r)
	var peek []byte
	peek, err = buf.Peek(512)
	if err != nil {
		if err != io.EOF {
			return
		}
	}
	detected := detectEncrypt(peek)
	enc, armored = detected.Encoding, detected.Armored
	switch enc {
	case EncryptEncoding:
		if armored {
			out, key, _, err = NewDecryptArmoredStream(buf, kr)
		} else {
			out, key, err = NewDecryptStream(buf, kr)
		}
	case SigncryptEncoding:
		if armored {
			out, key, _, err = NewSigncryptOpenArmoredStream(buf, kr)
		} else {
			out, key, err = NewSigncryptOpenStream(buf, kr)
		}
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
func NewDecryptStream(r io.Reader, kr Keyring) (io.Reader, *keys.X25519PublicKey, error) {
	sp := newSaltpack(kr)
	info, stream, err := ksaltpack.NewDecryptStream(encryptVersionValidator, r, sp)
	if err != nil {
		return nil, nil, convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, err
	}
	return stream, sender, nil
}

// NewDecryptArmoredStream creates a armored decrypt stream.
func NewDecryptArmoredStream(r io.Reader, kr Keyring) (io.Reader, *keys.X25519PublicKey, string, error) {
	sp := newSaltpack(kr)
	info, stream, brand, err := ksaltpack.NewDearmor62DecryptStream(encryptVersionValidator, r, sp)
	if err != nil {
		return nil, nil, "", convertBoxKeyErr(err)
	}
	sender, err := x25519SenderKey(info)
	if err != nil {
		return nil, nil, "", err
	}
	return stream, sender, brand, nil
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
