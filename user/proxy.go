package user

import (
	"context"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/json"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

type userStatus struct {
	ID         string  `json:"id,omitempty"`
	Name       string  `json:"name,omitempty"`
	KID        keys.ID `json:"kid,omitempty"`
	Seq        int     `json:"seq,omitempty"`
	Service    string  `json:"service,omitempty"`
	URL        string  `json:"url,omitempty"`
	Status     Status  `json:"status,omitempty"`
	VerifiedAt int64   `json:"verifiedAt,omitempty"`
	Timestamp  int64   `json:"ts,omitempty"`
	MatchField string  `json:"mf,omitempty"`
	Err        string  `json:"err,omitempty"`
}

// UpdateViaProxy looks at key.pub instead of requesting from the service
// directly.
func (r *Result) UpdateViaProxy(ctx context.Context, req request.Requestor, now time.Time) {
	usr, err := updateViaProxy(ctx, req, r.User)
	if err != nil {
		r.Err = err.Error()
		r.Status = StatusFailure
		return
	}
	r.Status = usr.Status
	r.Err = usr.Err
	r.Timestamp = tsutil.Millis(now)
	r.VerifiedAt = usr.VerifiedAt
}

func updateViaProxy(ctx context.Context, req request.Requestor, user *User) (*userStatus, error) {
	urs := "https://keys.pub/user/" + user.KID.String()
	b, err := req.Get(ctx, urs, nil)
	if err != nil {
		return nil, err
	}
	var status userStatus
	if err := json.Unmarshal(b, &status); err != nil {
		return nil, err
	}
	if user.KID != status.KID {
		return nil, errors.Errorf("invalid user kid")
	}
	if user.Name != status.Name {
		return nil, errors.Errorf("invalid user name")
	}
	if user.Seq != status.Seq {
		return nil, errors.Errorf("invalid user seq")
	}
	if user.Service != status.Service {
		return nil, errors.Errorf("invalid user service")
	}
	if user.URL != status.URL {
		return nil, errors.Errorf("invalid user url")
	}
	return &status, nil
}
