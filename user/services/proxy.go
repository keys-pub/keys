package services

import (
	"context"
	"fmt"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/validate"
	"github.com/pkg/errors"
)

type proxy struct{}

// Proxy uses keys.pub user cache instead of the service directly.
var Proxy = &proxy{}

func (s *proxy) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	if usr.Service != "twitter" {
		return user.StatusFailure, nil, errors.Errorf("invalid service")
	}
	name, id, err := validate.Twitter.NameStatusForURL(usr.URL)
	if err != nil {
		return user.StatusFailure, nil, errors.Errorf("invalid url")
	}

	url := fmt.Sprintf("https://keys.pub/twitter/%s/%s/%s", usr.KID, name, id)
	return Request(ctx, client, url, nil)
}

func (s *proxy) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, *Verified, error) {
	status, statement, err := user.FindVerify(usr, b, false)
	if err != nil {
		return status, nil, err
	}
	return status, &Verified{Statement: statement, Proxied: true}, nil
}
