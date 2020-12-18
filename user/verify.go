package user

import (
	"context"
	"fmt"

	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// RequestVerify requests a user URL and verifies it.
// The result.Status is success (StatusOK) or type of failure.
// If a failure, result.Err has the error message.
func (u *User) RequestVerify(ctx context.Context, opt ...VerifyOption) *Result {
	opts := newVerifyOptions(opt...)
	res := &Result{
		User: u,
	}
	res.Update(ctx, opts.Client, opts.Clock.Now())
	return res
}

// VerifyOptions ...
type VerifyOptions struct {
	Client http.Client
	Clock  tsutil.Clock
}

// VerifyOption ...
type VerifyOption func(*VerifyOptions)

// newVerifyOptions parses VerifyOptions.
func newVerifyOptions(opts ...VerifyOption) VerifyOptions {
	options := VerifyOptions{
		Client: http.NewClient(),
		Clock:  tsutil.NewClock(),
	}
	for _, o := range opts {
		o(&options)
	}
	return options
}

// Client ...
func Client(client http.Client) VerifyOption {
	return func(o *VerifyOptions) {
		o.Client = client
	}
}

// Clock ...
func Clock(clock tsutil.Clock) VerifyOption {
	return func(o *VerifyOptions) {
		o.Clock = clock
	}
}

// findVerify finds and verifies content in bytes.
func findVerify(usr *User, b []byte) (Status, error) {
	msg, _ := encoding.FindSaltpack(string(b), true)
	if msg == "" {
		logger.Warningf("User statement content not found")
		return StatusContentNotFound, errors.Errorf("user signed message content not found")
	}

	verifyMsg := fmt.Sprintf("BEGIN MESSAGE.\n%s\nEND MESSAGE.", msg)
	if err := usr.Verify(verifyMsg); err != nil {
		logger.Warningf("Failed to verify statement: %s", err)
		return StatusStatementInvalid, err
	}

	return StatusOK, nil
}
