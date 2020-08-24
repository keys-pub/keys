package user

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/link"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// RequestVerify requests a user URL and verifies it.
// The result.Status is success (StatusOK) or type of failure.
// If a failure, result.Err has the error message.
func RequestVerify(ctx context.Context, req request.Requestor, usr *User, now time.Time) *Result {
	res := &Result{
		User: usr,
	}
	updateResult(ctx, req, res, now)
	return res
}

func updateResult(ctx context.Context, req request.Requestor, result *Result, now time.Time) {
	logger.Infof("Update user %s", result.User.String())

	result.Timestamp = tsutil.Millis(now)

	service, err := link.NewService(result.User.Service)
	if err != nil {
		result.Err = err.Error()
		result.Status = StatusFailure
		return
	}

	logger.Debugf("Validate user name: %s, url: %s", result.User.Name, result.User.URL)
	urs, err := service.ValidateURLString(result.User.Name, result.User.URL)
	if err != nil {
		result.Err = err.Error()
		result.Status = StatusFailure
		return
	}

	// For test requests
	ur, err := url.Parse(urs)
	if err != nil {
		result.Err = err.Error()
		result.Status = StatusFailure
		return
	}

	var body []byte
	if ur.Scheme == "test" && ur.Host == "echo" {
		logger.Infof("Test echo request %s", urs)
		b, err := echoRequest(ur)
		if err != nil {
			result.Err = err.Error()
			result.Status = StatusFailure
			return
		}
		body = b
	} else {
		logger.Infof("Requesting %s", urs)
		b, err := req.RequestURLString(ctx, urs)
		if err != nil {
			logger.Warningf("Request failed: %v", err)
			if errHTTP, ok := errors.Cause(err).(request.ErrHTTP); ok && errHTTP.StatusCode == 404 {
				result.Err = err.Error()
				result.Status = StatusResourceNotFound
				return
			}
			result.Err = err.Error()
			result.Status = StatusConnFailure
			return
		}
		body = b
	}

	b, err := service.CheckContent(result.User.Name, body)
	if err != nil {
		logger.Warningf("Failed to check content: %s", err)
		result.Err = err.Error()
		result.Status = StatusContentInvalid
		return
	}

	st, err := FindVerify(b, result.User)
	if err != nil {
		logger.Warningf("Failed to find and verify: %s", err)
		result.Err = err.Error()
		result.Status = st
		return
	}

	logger.Infof("Verified %s", result.User.KID)
	result.Err = ""
	result.Status = StatusOK
	result.VerifiedAt = tsutil.Millis(now)
}

// FindVerify finds and verifies content.
func FindVerify(b []byte, user *User) (Status, error) {
	msg, _ := encoding.FindSaltpack(string(b), true)
	if msg == "" {
		logger.Warningf("User statement content not found")
		return StatusContentNotFound, errors.Errorf("user signed message content not found")
	}

	verifyMsg := fmt.Sprintf("BEGIN MESSAGE.\n%s\nEND MESSAGE.", msg)
	if err := Verify(verifyMsg, user); err != nil {
		logger.Warningf("Failed to verify statement: %s", err)
		return StatusStatementInvalid, err
	}

	return StatusOK, nil
}
