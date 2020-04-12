package secret

import (
	"encoding/json"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/keyring"
	"github.com/pkg/errors"
)

// Secret to keep.
type Secret struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type Type   `json:"type"`

	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	URL   string `json:"url,omitempty"`
	Notes string `json:"notes,omitempty"`

	Contact *Contact `json:"contact,omitempty"`
	Card    *Card    `json:"card,omitempty"`

	// History []*Secret `json:"history,omitempty"`

	CreatedAt time.Time `json:"createdAt,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

type Contact struct {
	FirstName string    `json:"firstName,omitempty"`
	LastName  string    `json:"lastName,omitempty"`
	Company   string    `json:"company,omitempty"`
	Emails    []string  `json:"emails,omitempty"`
	Phones    []string  `json:"phones,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
}

type Address struct {
	Address1   string `json:"address1,omitempty"`
	Address2   string `json:"address2,omitempty"`
	Address3   string `json:"address3,omitempty"`
	City       string `json:"city,omitempty"`  // Or Town
	State      string `json:"state,omitempty"` // Or Province
	PostalCode string `json:"zip,omitempty"`   // Or Postal Code
	Country    string `json:"country,omitempty"`
}

type Card struct {
	FullName   string `json:"fullName,omitempty"`
	Number     string `json:"number,omitempty"`
	Expiration string `json:"expire,omitempty"`
	Code       string `json:"code,omitempty"`
}

type Type string

const (
	UnknownType  Type = ""
	PasswordType Type = "password"
	ContactType  Type = "contact"
	CardType     Type = "card"
	NoteType     Type = "note"
)

// RandID creates a random secret ID.
func RandID() string {
	return keys.Rand3262()
}

// NewSecret creates a new Secret.
func NewSecret() *Secret {
	return &Secret{
		ID:        RandID(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// // Copy secret.
// func (s *Secret) Copy() *Secret {
// 	b, err := json.Marshal(s)
// 	if err != nil {
// 		panic(err)
// 	}
// 	var copy Secret
// 	if err := json.Unmarshal(b, &copy); err != nil {
// 		panic(err)
// 	}
// 	return &copy
// }

// // AddToHistory adds secret (copy) to history.
// func (s *Secret) AddToHistory(secret *Secret) {
// 	if s.History == nil {
// 		s.History = []*Secret{}
// 	}
// 	s.History = append(s.History, secret.Copy())
// }

const secretItemType string = "secret"

// newItem creates keyring item for a secret.
func newItem(secret *Secret) (*keyring.Item, error) {
	b, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	if secret.ID == "" {
		return nil, errors.Errorf("no secret id")
	}
	return keyring.NewItem(secret.ID, keyring.NewSecret(b), secretItemType), nil
}

// asSecret returns Secret for keyring Item.
func asSecret(item *keyring.Item) (*Secret, error) {
	if item.Type != secretItemType {
		return nil, errors.Errorf("item type %s != %s", item.Type, secretItemType)
	}
	var secret Secret
	if err := json.Unmarshal(item.SecretData(), &secret); err != nil {
		logger.Errorf("invalid secret item")
	}
	return &secret, nil
}
