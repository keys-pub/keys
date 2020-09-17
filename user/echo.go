package user

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
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

func echoRequest(ur *url.URL) ([]byte, error) {
	if ur.Scheme != "test" {
		return nil, errors.Errorf("invalid scheme for echo")
	}
	if ur.Host != "echo" {
		return nil, errors.Errorf("invalid host for echo")
	}

	path := ur.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 3 {
		return nil, errors.Errorf("path invalid %s", path)
	}
	username := paths[0]
	kid, err := keys.ParseID(paths[1])
	if err != nil {
		return nil, err
	}
	msg := paths[2]
	un, err := url.QueryUnescape(msg)
	if err != nil {
		return nil, err
	}
	msg = un

	usr := &User{
		Service: "echo",
		KID:     kid,
		Name:    username,
	}

	if err := usr.Verify(msg); err != nil {
		return nil, err
	}

	return []byte(msg), nil

}
