package request

import (
	"context"
	"time"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/keys-pub/keys/user/services"
	"github.com/pkg/errors"
)

// Verify get user URL using client and verifies it.
// If there is an error, it is set on the result.
func Verify(ctx context.Context, client http.Client, usr *user.User) (user.Status, string, error) {
	service, err := services.Lookup(usr.Service)
	if err != nil {
		return user.StatusFailure, "", err
	}

	st, body, err := service.Request(ctx, client, usr)
	if err != nil {
		return st, "", err
	}
	if st != user.StatusOK {
		return st, "", err
	}
	if body == nil {
		return user.StatusResourceNotFound, "", errors.Errorf("resource not found")
	}

	st, msg, err := service.Verify(ctx, body, usr)
	if err != nil {
		logger.Warningf("Failed to check content: %s", err)
		return st, "", err
	}

	return st, msg, nil
}

// UpdateResult updates a user.Result using client.
// The result.Status is success (StatusOK) or type of failure.
// If a failure, result.Err has the error message.
func UpdateResult(ctx context.Context, result *user.Result, client http.Client, now time.Time) {
	logger.Infof("Update user %s", result.User.String())

	result.Timestamp = tsutil.Millis(now)
	st, msg, err := Verify(ctx, client, result.User)
	if err != nil {
		result.Err = err.Error()
		result.Status = st
		result.Statement = ""
		return
	}

	logger.Infof("Verified %s", result.User.KID)
	result.Err = ""
	result.Statement = msg
	result.Status = st
	result.VerifiedAt = tsutil.Millis(now)
}
