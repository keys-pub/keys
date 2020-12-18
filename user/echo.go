package user

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys"
)

// NewEcho creates a signed user@echo (for testing).
func NewEcho(sk *keys.EdX25519Key, name string, seq int) (*User, error) {
	usr, err := NewForSigning(sk.ID(), "echo", name)
	if err != nil {
		return nil, err
	}
	msg, err := usr.Sign(sk)
	if err != nil {
		return nil, err
	}
	urs := "test://echo/alice/" + sk.ID().String() + "/" + url.QueryEscape(strings.ReplaceAll(msg, "\n", " "))
	return New(sk.ID(), "echo", name, urs, seq)
}
