package user

import (
	"context"
	"fmt"
	"time"

	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
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

// Update result using client.
// If there is an error, it is set on the result.
func (r *Result) Update(ctx context.Context, client http.Client, now time.Time) {
	logger.Infof("Update user %s", r.User.String())

	r.Timestamp = tsutil.Millis(now)
	st, err := RequestVerify(ctx, client, r.User)
	if err != nil {
		r.Err = err.Error()
		r.Status = st
		return
	}

	logger.Infof("Verified %s", r.User.KID)
	r.Err = ""
	r.Status = st
	r.VerifiedAt = tsutil.Millis(now)
}
