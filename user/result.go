package user

import (
	"fmt"
	"time"

	"github.com/keys-pub/keys/tsutil"
)

// Result describes the status of a User.
// TODO: Make Err/Status more explicit, it can be confusing.
type Result struct {
	// Err if error occured.
	// See Status for type of error.
	Err string `json:"err,omitempty"`
	// Status for result. StatusOK if ok, otherwise an error type.
	Status Status `json:"status"`
	// Timestamp is the when the status was last updated.
	Timestamp int64 `json:"ts"`
	// User.
	User *User `json:"user"`
	// Statement we found at User.URL.
	Statement string `json:"statement,omitempty"`
	// Proxied if result was through a proxy.
	Proxied bool `json:"proxied,omitempty"`
	// VerifiedAt is when the status was last OK.
	VerifiedAt int64 `json:"vts,omitempty"`
}

func (r Result) String() string {
	if r.Status == StatusOK {
		return fmt.Sprintf("%s:%s(%d)", r.Status, r.User, r.VerifiedAt)
	}
	return fmt.Sprintf("%s:%s;err=%s", r.Status, r.User, r.Err)
}

// IsTimestampExpired returns true if result Timestamp is older than dt.
func (r Result) IsTimestampExpired(now time.Time, dt time.Duration) bool {
	ts := tsutil.ParseMillis(r.Timestamp)
	return (ts.IsZero() || now.Sub(ts) > dt)
}

// IsVerifyExpired returns true if result VerifiedAt is older than dt.
func (r Result) IsVerifyExpired(now time.Time, dt time.Duration) bool {
	ts := tsutil.ParseMillis(r.VerifiedAt)
	return (ts.IsZero() || now.Sub(ts) > dt)
}
