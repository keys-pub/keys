package services

import (
	"context"
	"net/url"
	"strings"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
)

type echo struct{}

// Echo service.
var Echo = &echo{}

func (s *echo) ID() string {
	return "echo"
}

func (s *echo) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	ur, err := url.Parse(usr.URL)
	if err != nil {
		return user.StatusFailure, nil, err
	}
	if ur.Scheme != "test" {
		return user.StatusFailure, nil, errors.Errorf("invalid scheme for echo")
	}
	if ur.Host != "echo" {
		return user.StatusFailure, nil, errors.Errorf("invalid host for echo")
	}

	path := ur.Path
	path = strings.TrimPrefix(path, "/")
	paths := strings.Split(path, "/")
	if len(paths) != 3 {
		return user.StatusFailure, nil, errors.Errorf("path invalid %s", path)
	}
	msg, err := url.QueryUnescape(paths[2])
	if err != nil {
		return user.StatusFailure, nil, err
	}

	if err := usr.Verify(msg); err != nil {
		return user.StatusFailure, nil, err
	}

	return user.StatusOK, []byte(msg), nil
}

func (s *echo) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, *Verified, error) {
	status, statement, err := user.FindVerify(usr, b, false)
	if err != nil {
		return status, nil, err
	}
	return status, &Verified{Statement: statement}, nil
}
