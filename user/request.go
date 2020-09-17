package user

import (
	"context"
	"fmt"
	"time"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/request"
	"github.com/pkg/errors"
)

// Verify requests a user URL and verifies it.
// The result.Status is success (StatusOK) or type of failure.
// If a failure, result.Err has the error message.
func (u *User) Verify(ctx context.Context, req request.Requestor, now time.Time) *Result {
	res := &Result{
		User: u,
	}
	res.Update(ctx, req, now)
	return res
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
