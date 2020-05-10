package user

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/link"
	"github.com/keys-pub/keys/util"
	"github.com/pkg/errors"
)

// RequestAndVerify a user URL.
func RequestAndVerify(ctx context.Context, req util.Requestor, usr *User, now time.Time) *Result {
	res := &Result{
		User: usr,
	}
	updateResult(ctx, req, usr, res, now)
	return res
}

func updateResult(ctx context.Context, req util.Requestor, usr *User, result *Result, now time.Time) {
	if result == nil {
		panic("no user result specified")
	}
	logger.Infof("Update user %s", result.User.String())

	if !userEqual(usr, result.User) {
		result.Err = "user and result user are not equal"
		result.Status = StatusFailure
		return
	}

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

	result.Timestamp = util.TimeToMillis(now)

	logger.Infof("Requesting %s", urs)
	body, err := req.RequestURLString(ctx, urs)
	if err != nil {
		logger.Warningf("Request failed: %v", err)
		if errHTTP, ok := errors.Cause(err).(util.ErrHTTP); ok && errHTTP.StatusCode == 404 {
			result.Err = err.Error()
			result.Status = StatusResourceNotFound
			return
		}
		result.Err = err.Error()
		result.Status = StatusConnFailure
		return
	}

	b, err := service.CheckContent(result.User.Name, body)
	if err != nil {
		logger.Warningf("Failed to check content: %s", err)
		result.Err = err.Error()
		result.Status = StatusContentInvalid
		return
	}

	st, err := VerifyContent(b, result, usr.KID)
	if err != nil {
		logger.Warningf("Failed to verify content: %s", err)
		result.Err = err.Error()
		result.Status = st
		return
	}

	logger.Infof("Verified %s", result.User.KID)
	result.Err = ""
	result.Status = StatusOK
	result.VerifiedAt = util.TimeToMillis(now)
}

func userEqual(usr1 *User, usr2 *User) bool {
	b1, err := json.Marshal(usr1)
	if err != nil {
		panic(err)
	}
	b2, err := json.Marshal(usr2)
	if err != nil {
		panic(err)
	}
	return bytes.Equal(b1, b2)
}

// VerifyContent checks content.
func VerifyContent(b []byte, result *Result, kid keys.ID) (Status, error) {
	msg, _ := encoding.FindSaltpack(string(b), true)
	if msg == "" {
		logger.Warningf("User statement content not found")
		return StatusContentNotFound, errors.Errorf("user signed message content not found")
	}

	verifyMsg := fmt.Sprintf("BEGIN MESSAGE.\n%s\nEND MESSAGE.", msg)
	if _, err := Verify(verifyMsg, kid, result.User); err != nil {
		logger.Warningf("Failed to verify statement: %s", err)
		return StatusStatementInvalid, err
	}

	return StatusOK, nil
}
