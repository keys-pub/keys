package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
)

type keyspub struct{}

// KeysPub uses keys.pub user cache instead of the service directly.
var KeysPub = &keyspub{}

func (s *keyspub) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	url := fmt.Sprintf("https://keys.pub/user/%s@%s", usr.Name, usr.Service)
	return Request(ctx, client, url, nil)
}

func (s *keyspub) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, *Verified, error) {
	userStatus, err := s.checkContent(usr, b)
	if err != nil {
		return user.StatusContentInvalid, nil, err
	}
	status, statement, err := user.FindVerify(usr, []byte(userStatus.Statement), false)
	if err != nil {
		return status, nil, err
	}

	verified := &Verified{Statement: statement, Timestamp: userStatus.VerifiedAt, Proxied: true}
	return status, verified, nil
}

func (s *keyspub) checkContent(usr *user.User, b []byte) (*userStatus, error) {
	var status struct {
		User userStatus `json:"user"`
	}
	if err := json.Unmarshal(b, &status); err != nil {
		return nil, err
	}
	us := status.User
	if us.Status != user.StatusOK {
		return nil, errors.Errorf("status not ok (%s)", us.Status)
	}

	if us.KID != usr.KID {
		return nil, errors.Errorf("invalid user kid")
	}

	if us.Name != usr.Name {
		return nil, errors.Errorf("invalid user name")
	}

	if us.Service != usr.Service {
		return nil, errors.Errorf("invalid user service")
	}

	if us.Seq != usr.Seq {
		return nil, errors.Errorf("invalid user seq")
	}

	if us.URL != usr.URL {
		return nil, errors.Errorf("invalid user url")
	}

	return &us, nil
}

type userStatus struct {
	ID         string      `json:"id,omitempty"`
	Name       string      `json:"name,omitempty"`
	KID        keys.ID     `json:"kid,omitempty"`
	Seq        int         `json:"seq,omitempty"`
	Service    string      `json:"service,omitempty"`
	URL        string      `json:"url,omitempty"`
	Status     user.Status `json:"status,omitempty"`
	Statement  string      `json:"statement,omitempty"`
	VerifiedAt int64       `json:"verifiedAt,omitempty"`
	Timestamp  int64       `json:"ts,omitempty"`
	MatchField string      `json:"mf,omitempty"`
	Err        string      `json:"err,omitempty"`
}
