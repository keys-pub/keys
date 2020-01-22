package saltpack

import (
	"crypto/subtle"

	ksaltpack "github.com/keybase/saltpack"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// Saltpack provider.
type Saltpack struct {
	keys       Keystore
	armor      bool
	armorBrand string
}

// Keystore ...
type Keystore interface {
	BoxPublicKey(id keys.ID) (*keys.BoxPublicKey, error)
	BoxKeys() ([]*keys.BoxKey, error)
}

// NewSaltpack creates a Saltpack provider.
// Uses signcryption, see .
func NewSaltpack(keys Keystore) *Saltpack {
	return &Saltpack{
		keys: keys,
	}
}

func signVersionValidator(version ksaltpack.Version) error {
	switch version.Major {
	case 1:
		return nil
	default:
		return errors.Errorf("unrecognized version %d.%d", version.Major, version.Minor)
	}
}

func signcryptVersionValidator(version ksaltpack.Version) error {
	switch version.Major {
	case 1:
		return nil
	default:
		return errors.Errorf("unrecognized version %d.%d", version.Major, version.Minor)
	}
}

func encryptVersionValidator(version ksaltpack.Version) error {
	switch version.Major {
	case 1, 2:
		return nil
	default:
		return errors.Errorf("unrecognized version %d.%d", version.Major, version.Minor)
	}
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
	bk := generateBoxKey()
	return bk, nil
}

// LookupBoxSecretKey looks in the Keyring for the secret key corresponding
// to one of the given Key IDs. Returns the index and the key on success,
// or -1 and nil on failure.
func (s *Saltpack) LookupBoxSecretKey(kids [][]byte) (int, ksaltpack.BoxSecretKey) {
	if s.keys == nil {
		logger.Errorf("Failed to list all box keys: no keystore")
		return -1, nil
	}
	bks, err := s.keys.BoxKeys()
	if err != nil {
		logger.Errorf("Failed to list all box keys: %v", err)
		return -1, nil
	}
	for i := 0; i < len(bks); i++ {
		for j := 0; j < len(kids); j++ {
			if subtle.ConstantTimeCompare(bks[i].PublicKey().Bytes()[:], kids[j]) == 1 {
				return j, newBoxKey(bks[i])
			}
		}
	}
	return -1, nil
}

// LookupBoxPublicKey returns a public key given the specified key ID.
// For most cases, the key ID will be the key itself.
func (s *Saltpack) LookupBoxPublicKey(kid []byte) ksaltpack.BoxPublicKey {
	if len(kid) != 32 {
		logger.Errorf("LookupBoxPublicKey len(kid) != 32")
		return nil
	}
	return newBoxPublicKey(keys.NewBoxPublicKey(keys.Bytes32(kid)))
}

// GetAllBoxSecretKeys returns all keys, needed if we want to support "hidden"
// receivers via trial and error.
func (s *Saltpack) GetAllBoxSecretKeys() []ksaltpack.BoxSecretKey {
	logger.Infof("List box keys...")
	if s.keys == nil {
		logger.Errorf("Failed to list all box keys: no keystore")
		return nil
	}
	bks, err := s.keys.BoxKeys()
	if err != nil {
		logger.Errorf("Failed to list all box keys: %v", err)
		return nil
	}
	boxSecretKeys := make([]ksaltpack.BoxSecretKey, 0, len(bks))
	for _, k := range bks {
		boxSecretKeys = append(boxSecretKeys, newBoxKey(k))
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
	if len(b) != 32 {
		logger.Errorf("Invalid signing public key bytes")
		return nil
	}
	spk := keys.Bytes32(b)
	return newSignPublicKey(keys.NewSignPublicKey(spk))
}

func (s *Saltpack) boxPublicKeys(recipients []keys.ID) ([]ksaltpack.BoxPublicKey, error) {
	publicKeys := make([]ksaltpack.BoxPublicKey, 0, len(recipients))
	for _, r := range recipients {
		pk, err := s.keys.BoxPublicKey(r)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid recipient")
		}
		publicKeys = append(publicKeys, newBoxPublicKey(pk))
	}
	return publicKeys, nil
}
