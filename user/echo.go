package user

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

func echoRequest(ur *url.URL) ([]byte, error) {
	if ur.Scheme != "test" {
		return nil, errors.Errorf("invalid test scheme")
	}
	if ur.Host != "echo" {
		return nil, errors.Errorf("invalid echo host")
	}

	path := ur.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 2 {
		return nil, errors.Errorf("path invalid %s", path)
	}
	username := paths[0]
	kid, err := keys.ParseID(paths[1])
	if err != nil {
		return nil, err
	}

	msg := ur.Query().Get("s")
	user := &User{
		Service: "echo",
		KID:     kid,
		Name:    username,
	}

	if err := Verify(msg, user); err != nil {
		return nil, err
	}

	return []byte(msg), nil

}
