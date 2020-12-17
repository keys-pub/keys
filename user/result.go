package user

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// Result describes the status of a User.
// TODO: Make Err/Status more explicit, it can be confusing.
type Result struct {
	Err    string `json:"err,omitempty"`
	Status Status `json:"status"`
	// Timestamp is the when the status was last updated.
	Timestamp int64 `json:"ts"`
	User      *User `json:"user"`
	// VerifiedAt is when the status was last OK.
	VerifiedAt int64 `json:"vts"`
}

func (r Result) String() string {
	if r.Status == StatusOK {
		return fmt.Sprintf("%s:%s(%d)", r.Status, r.User, r.VerifiedAt)
	}
	return fmt.Sprintf("%s:%s;err=%s", r.Status, r.User, r.Err)
}

// IsTimestampExpired returns true if result Timestamp is older than dt.
func (r Result) IsTimestampExpired(now time.Time, dt time.Duration) bool {
	ts := tsutil.ConvertMillis(r.Timestamp)
	return (ts.IsZero() || now.Sub(ts) > dt)
}

// IsVerifyExpired returns true if result VerifiedAt is older than dt.
func (r Result) IsVerifyExpired(now time.Time, dt time.Duration) bool {
	ts := tsutil.ConvertMillis(r.VerifiedAt)
	return (ts.IsZero() || now.Sub(ts) > dt)
}

// Update result using Requestor.
func (r *Result) Update(ctx context.Context, req request.Requestor, now time.Time) {
	logger.Infof("Update user %s", r.User.String())

	r.Timestamp = tsutil.Millis(now)

	service, err := lookupService(r.User.Service)
	if err != nil {
		r.Err = err.Error()
		r.Status = StatusFailure
		return
	}

	logger.Debugf("Validate user name: %s, url: %s", r.User.Name, r.User.URL)
	urs, err := service.ValidateURLString(r.User.Name, r.User.URL)
	if err != nil {
		r.Err = err.Error()
		r.Status = StatusFailure
		return
	}

	ur, err := url.Parse(urs)
	if err != nil {
		r.Err = err.Error()
		r.Status = StatusFailure
		return
	}

	headers, err := service.Headers(ur)
	if err != nil {
		r.Err = err.Error()
		r.Status = StatusFailure
		return
	}

	var body []byte
	if ur.Scheme == "test" && ur.Host == "echo" {
		// For test requests
		logger.Infof("Test echo request %s", urs)
		b, err := echoRequest(ur)
		if err != nil {
			r.Err = err.Error()
			r.Status = StatusFailure
			return
		}
		body = b
	} else {
		logger.Infof("Requesting %s", urs)
		b, err := req.RequestURLString(ctx, urs, headers)
		if err != nil {
			logger.Warningf("Request failed: %v", err)
			if errHTTP, ok := errors.Cause(err).(request.ErrHTTP); ok && errHTTP.StatusCode == 404 {
				r.Err = err.Error()
				r.Status = StatusResourceNotFound
				return
			}
			r.Err = err.Error()
			r.Status = StatusConnFailure
			return
		}
		body = b
	}

	b, err := service.CheckContent(r.User.Name, body)
	if err != nil {
		logger.Warningf("Failed to check content: %s", err)
		r.Err = err.Error()
		r.Status = StatusContentInvalid
		return
	}

	st, err := findVerify(r.User, b)
	if err != nil {
		logger.Warningf("Failed to find and verify: %s", err)
		r.Err = err.Error()
		r.Status = st
		return
	}

	logger.Infof("Verified %s", r.User.KID)
	r.Err = ""
	r.Status = StatusOK
	r.VerifiedAt = tsutil.Millis(now)
}
