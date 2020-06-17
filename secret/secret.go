// Package secret defines secret types for storing in a keyring.
package secret

import (
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
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

// Contact ...
type Contact struct {
	FirstName string    `json:"firstName,omitempty"`
	LastName  string    `json:"lastName,omitempty"`
	Company   string    `json:"company,omitempty"`
	Emails    []string  `json:"emails,omitempty"`
	Phones    []string  `json:"phones,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
}

// Address ...
type Address struct {
	Address1   string `json:"address1,omitempty"`
	Address2   string `json:"address2,omitempty"`
	Address3   string `json:"address3,omitempty"`
	City       string `json:"city,omitempty"`  // Or Town
	State      string `json:"state,omitempty"` // Or Province
	PostalCode string `json:"zip,omitempty"`   // Or Postal Code
	Country    string `json:"country,omitempty"`
}

// Card ...
type Card struct {
	FullName   string `json:"fullName,omitempty"`
	Number     string `json:"number,omitempty"`
	Expiration string `json:"expire,omitempty"`
	Code       string `json:"code,omitempty"`
}

// Type for secret.
type Type string

const (
	// UnknownType ...
	UnknownType Type = ""
	// PasswordType ...
	PasswordType Type = "password"
	// ContactType ...
	ContactType Type = "contact"
	// CardType ...
	CardType Type = "card"
	// NoteType ...
	NoteType Type = "note"
)

// RandID creates a random secret ID.
func RandID() string {
	return encoding.MustEncode(keys.RandBytes(32), encoding.Base62)
}

// NewSecret creates a new Secret.
func NewSecret() *Secret {
	return &Secret{
		ID:        RandID(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
