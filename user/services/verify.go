package services

import (
	"context"
	"time"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
)

// Verify a user.
// The result.Status is success (StatusOK) or type of failure.
// If a failure, result.Err has the error message.
func Verify(ctx context.Context, service Service, client http.Client, usr *user.User) *user.Result {
	result := &user.Result{User: usr}
	UpdateResult(ctx, service, result, client, time.Now())
	return result
}

// UpdateResult updates a user.Result.
// The result.Status is success (StatusOK) or type of failure.
// If a failure, result.Err has the error message.
func UpdateResult(ctx context.Context, service Service, result *user.Result, client http.Client, now time.Time) {
	logger.Infof("Update user %s", result.User.String())

	result.Timestamp = tsutil.Millis(now)
	status, verified, err := requestVerify(ctx, service, client, result.User)
	if err != nil {
		result.Err = err.Error()
		result.Status = status
		result.Statement = ""
		return
	}

	logger.Infof("Verified %s", result.User.KID)
	result.Err = ""
	result.Status = status
	result.Statement = verified.Statement
	result.Proxied = verified.Proxied
	if verified.Timestamp != 0 {
		result.VerifiedAt = verified.Timestamp
	} else {
		result.VerifiedAt = tsutil.Millis(now)
	}
}

// requestVerify get user URL using client and verifies it.
// If there is an error, it is set on the result.
func requestVerify(ctx context.Context, service Service, client http.Client, usr *user.User) (user.Status, *Verified, error) {
	st, body, err := service.Request(ctx, client, usr)
	if err != nil {
		return st, nil, err
	}
	if st != user.StatusOK {
		return st, nil, err
	}
	if body == nil {
		return user.StatusResourceNotFound, nil, errors.Errorf("resource not found")
	}

	st, msg, err := service.Verify(ctx, body, usr)
	if err != nil {
		logger.Warningf("Failed to check content: %s", err)
		return st, nil, err
	}

	return st, msg, nil
}
