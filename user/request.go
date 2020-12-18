package user

import (
	"context"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user/services"
	"github.com/pkg/errors"
)

// requestVerify user URL using client.
// If there is an error, it is set on the result.
func requestVerify(ctx context.Context, client http.Client, usr *User) (Status, string, error) {
	service, err := services.Lookup(usr.Service)
	if err != nil {
		return StatusFailure, "", err
	}

	logger.Debugf("Validate user name: %s, url: %s", usr.Name, usr.URL)
	urs, err := service.ValidateURL(usr.Name, usr.URL)
	if err != nil {
		return StatusFailure, "", err
	}

	body, err := service.Request(ctx, client, urs)
	if err != nil {
		return StatusConnFailure, "", err
	}
	if body == nil {
		return StatusResourceNotFound, "", errors.Errorf("resource not found")
	}

	b, err := service.CheckContent(usr.Name, body)
	if err != nil {
		logger.Warningf("Failed to check content: %s", err)
		return StatusContentInvalid, "", err
	}

	st, msg, err := findVerify(usr, b)
	if err != nil {
		logger.Warningf("Failed to find and verify: %s", err)
		return st, "", err
	}

	return StatusOK, msg, nil
}
