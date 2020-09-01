package user

import (
	"fmt"
	"time"

	"github.com/keys-pub/keys"
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

type keyDocument struct {
	KID     keys.ID   `json:"kid"`
	Results []*Result `json:"results,omitempty"`

	// Result for backwards compatibility.
	// TODO: Remove after full re-index.
	Result *Result `json:"result,omitempty"`
}

// existingResults for backwards compatibility.
// TODO: Remove after full re-index.
func (k *keyDocument) resultsForCompatibility() []*Result {
	if k.Result != nil {
		return []*Result{k.Result}
	}
	return k.Results
}

type userDocument struct {
	KID    keys.ID `json:"kid"`
	Result *Result `json:"result,omitempty"`
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
