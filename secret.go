package keys

import (
	"encoding/json"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Secret to keep.
type Secret struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Data []byte `json:"data,omitempty"`
	Type string `json:"type,omitempty"`

	Website string `json:"website,omitempty"`
	Notes   string `json:"notes,omitempty"`

	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// RandSecretID creates a random secret ID.
func RandSecretID() string {
	return Rand3262()
}

// NewSecret creates a new Secret.
func NewSecret() *Secret {
	return &Secret{
		ID:        RandSecretID(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// SecretStore can saves to the keyring.
type SecretStore struct {
	kr    keyring.Keyring
	nowFn func() time.Time
}

// NewKeystore constructs a Keystore.
func NewSecretStore(kr keyring.Keyring) *SecretStore {
	return &SecretStore{
		kr: kr,
	}
}

// SetTimeNow sets clock.
func (s *SecretStore) SetTimeNow(nowFn func() time.Time) {
	s.nowFn = nowFn
}

// SaveSecret saves a secret.
func (s *SecretStore) SaveSecret(secret *Secret) error {
	secret.UpdatedAt = s.nowFn()
	item, err := NewSecretItem(secret)
	if err != nil {
		return err
	}
	return s.kr.Set(item)
}

// Secret for ID.
func (s *SecretStore) Secret(id string) (*Secret, error) {
	item, err := s.kr.Get(id)
	if err != nil {
		return nil, err
	}
	return AsSecret(item)
}

type SecretsOpts struct{}

// Secrets lists secrets.
func (s *SecretStore) Secrets(opts *SecretsOpts) ([]*Secret, error) {
	// if opts == nil {
	// 	opts = &SecretsOpts{}
	// }
	logger.Debugf("Listing secrets...")
	items, err := s.kr.List(&keyring.ListOpts{
		Types: []string{secretItemType},
	})
	if err != nil {
		return nil, err
	}
	secrets := make([]*Secret, 0, len(items))
	for _, item := range items {
		secret, err := AsSecret(item)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	logger.Debugf("Found %d secrets", len(secrets))
	return secrets, nil
}

// NewSecretItem creates keyring item for a secret.
func NewSecretItem(secret *Secret) (*keyring.Item, error) {
	b, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	if secret.ID == "" {
		return nil, errors.Errorf("no secret id")
	}
	return keyring.NewItem(secret.ID, keyring.NewSecret(b), secretItemType), nil
}

// AsSecret returns Secret for keyring Item.
func AsSecret(item *keyring.Item) (*Secret, error) {
	if item.Type != secretItemType {
		return nil, errors.Errorf("item type %s != %s", item.Type, secretItemType)
	}
	var secret Secret
	if err := json.Unmarshal(item.SecretData(), &secret); err != nil {
		logger.Errorf("invalid secret item")
	}
	return &secret, nil
}
