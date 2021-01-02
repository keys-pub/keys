package api

import (
	"strings"

	"github.com/keys-pub/keys"
)

// ParseKey tries to determine what key type and parses the key bytes.
func ParseKey(b []byte, password string) (*Key, error) {
	s := strings.TrimSpace(string(b))

	kid, err := keys.ParseID(s)
	if err == nil {
		return NewKey(kid), nil
	}

	if strings.HasPrefix(s, "ssh-") {
		out, err := keys.ParseSSHPublicKey(s)
		if err != nil {
			return nil, err
		}
		return NewKey(out), err
	}

	if strings.HasPrefix(s, "-----BEGIN ") {
		out, err := keys.ParseSSHKey([]byte(s), []byte(password), true)
		if err != nil {
			return nil, err
		}
		return NewKey(out), err
	}

	return DecodeKey(s, password)
}
