package secret

import (
	"strings"
	"time"

	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Store can saves to the keyring.
type Store struct {
	kr    *keyring.Keyring
	nowFn func() time.Time
}

// NewStore constructs a secret.Store.
func NewStore(kr *keyring.Keyring) *Store {
	return &Store{
		kr:    kr,
		nowFn: time.Now,
	}
}

// SetTimeNow sets clock.
func (s *Store) SetTimeNow(nowFn func() time.Time) {
	s.nowFn = nowFn
}

// Set a secret.
// Returns true if secret was updated.
func (s *Store) Set(secret *Secret) (*Secret, bool, error) {
	if secret == nil {
		return nil, false, errors.Errorf("nil secret")
	}

	if strings.TrimSpace(secret.ID) == "" {
		return nil, false, errors.Errorf("no secret id")
	}

	existing, err := s.Get(secret.ID)
	if err != nil {
		return nil, false, err
	}

	updated := false
	if existing != nil {
		secret.CreatedAt = existing.CreatedAt
		secret.UpdatedAt = s.nowFn()
		b := marshalSecret(secret)
		if err := s.kr.Update(secret.ID, b); err != nil {
			return nil, false, err
		}
		updated = true

	} else {
		now := s.nowFn()
		secret.CreatedAt = now
		secret.UpdatedAt = now

		item, err := newItem(secret)
		if err != nil {
			return nil, false, err
		}
		if err := s.kr.Create(item); err != nil {
			return nil, false, err
		}
	}

	return secret, updated, nil
}

// Delete a secret.
func (s *Store) Delete(id string) (bool, error) {
	return s.kr.Delete(id)
}

// Get secret for ID.
func (s *Store) Get(id string) (*Secret, error) {
	item, err := s.kr.Get(id)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, nil
	}
	return asSecret(item)
}

// ListOpts are options for listing secrets.
type ListOpts struct{}

// List secrets.
func (s *Store) List() ([]*Secret, error) {
	logger.Debugf("Listing secrets...")
	items, err := s.kr.List(keyring.WithTypes(secretItemType))
	if err != nil {
		return nil, err
	}
	secrets := make([]*Secret, 0, len(items))
	for _, item := range items {
		secret, err := asSecret(item)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	logger.Debugf("Found %d secrets", len(secrets))
	return secrets, nil
}
