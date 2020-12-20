package services

import (
	"context"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
)

type https struct{}

// HTTPS service.
var HTTPS = &https{}

func (s *https) ID() string {
	return "https"
}

func (s *https) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	return Request(ctx, client, usr.URL, nil)
}

func (s *https) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, string, error) {
	return user.FindVerify(usr, []byte(b), false)
}
