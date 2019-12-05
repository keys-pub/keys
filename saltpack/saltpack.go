package saltpack

import (
	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

var _ keys.CryptoProvider = &Saltpack{}
var _ keys.CryptoStreamProvider = &Saltpack{}

// Mode for encyption (signcrypt, encrypt)
type Mode string

const (
	// SigncryptMode https://saltpack.org/signcryption-format.
	// Recipients can't forge the message (non-repudiability).
	SigncryptMode Mode = "signcrypt"
	// EncryptMode see https://saltpack.org/encryption-format-v2.
	// Recipients can forge the message (repudiability).
	EncryptMode Mode = "encrypt"
)

// Saltpack provider.
type Saltpack struct {
	ks         *keys.Keystore
	armor      bool
	armorBrand string
	mode       Mode
}

// NewSaltpack creates a new keys.CryptoProvider using Saltpack.
// The default mode is Signcryption, see https://saltpack.org/signcryption-format.
func NewSaltpack(ks *keys.Keystore) *Saltpack {
	return &Saltpack{
		ks:   ks,
		mode: SigncryptMode,
	}
}

func versionValidator(version ksaltpack.Version) error {
	switch version.Major {
	case 1, 2:
		return nil
	default:
		return errors.Errorf("unrecognized version")
	}
}

// SetMode to set the mode.
func (s *Saltpack) SetMode(m Mode) {
	if m == EncryptMode {
		panic("encrypt mode is currently unsupported")
	}
	s.mode = m
}

// Mode ...
func (s *Saltpack) Mode() Mode {
	return s.mode
}

// SetArmored to set whether data is armored.
func (s *Saltpack) SetArmored(b bool) {
	s.armor = b
}

// Armored ...
func (s *Saltpack) Armored() bool {
	return s.armor
}

// SetArmorBrand sets the armor brand (if armored).
func (s *Saltpack) SetArmorBrand(brand string) {
	s.armorBrand = brand
}

// ArmorBrand ...
func (s *Saltpack) ArmorBrand() string {
	return s.armorBrand
}

// CreateEphemeralKey creates a random ephemeral key.
func (s *Saltpack) CreateEphemeralKey() (ksaltpack.BoxSecretKey, error) {
	bk := GenerateBoxKey()
	return bk, nil
}

// LookupBoxSecretKey looks in the Keyring for the secret key corresponding
// to one of the given Key IDs. Returns the index and the key on success,
// or -1 and nil on failure.
func (s *Saltpack) LookupBoxSecretKey(kids [][]byte) (int, ksaltpack.BoxSecretKey) {
	panic("not implemented")
}

// LookupBoxPublicKey returns a public key given the specified key ID.
// For most cases, the key ID will be the key itself.
func (s *Saltpack) LookupBoxPublicKey(kid []byte) ksaltpack.BoxPublicKey {
	panic("not implemented")
}

// GetAllBoxSecretKeys returns all keys, needed if we want to support "hidden"
// receivers via trial and error.
func (s *Saltpack) GetAllBoxSecretKeys() []ksaltpack.BoxSecretKey {
	logger.Infof("List keys...")
	ks, err := s.ks.Keys()
	if err != nil {
		logger.Errorf("Failed to list keys: %v", err)
		return nil
	}
	boxSecretKeys := make([]ksaltpack.BoxSecretKey, 0, len(ks))
	for _, k := range ks {
		boxSecretKeys = append(boxSecretKeys, NewBoxKey(k.BoxKey()))
	}
	return boxSecretKeys
}

// ImportBoxEphemeralKey imports the ephemeral key into BoxPublicKey format.
// This key has never been seen before, so will be ephemeral.
func (s *Saltpack) ImportBoxEphemeralKey(kid []byte) ksaltpack.BoxPublicKey {
	return boxPublicKeyFromKID(kid)
}

// LookupSigningPublicKey (for ksaltpack.SigKeyring)
func (s *Saltpack) LookupSigningPublicKey(b []byte) ksaltpack.SigningPublicKey {
	kid, err := keys.NewID(b)
	if err != nil {
		logger.Errorf("Failed to saltpack lookup public key: %v", err)
		return nil
	}

	// logger.Debugf("Lookup SigningPublicKey for %s", kid)
	// pk, pkErr := s.ks.PublicKey(kid)
	// if pkErr != nil {
	// 	logger.Errorf("Failed to saltpack lookup public key: %v", pkErr)
	// 	return nil
	// }
	// if pk != nil {
	// 	return NewSignPublicKey(pk.SignPublicKey())
	// }

	spk, err := keys.DecodeSignPublicKey(kid.String())
	if err != nil {
		logger.Errorf("Failed to saltpack lookup public key: %v", err)
		return nil
	}
	return NewSignPublicKey(spk)
}
