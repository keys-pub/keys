package user

import (
	"net/url"
	"strings"

	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

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

	if err := Verify(msg, usr); err != nil {
		return nil, err
	}

	return []byte(msg), nil

}
