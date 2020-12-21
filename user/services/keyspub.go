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

type kpUser struct{}

// KeysPub uses keys.pub user cache instead of the service directly.
var KeysPub = &kpUser{}

func (s *kpUser) Request(ctx context.Context, client http.Client, usr *user.User) (user.Status, []byte, error) {
	url := fmt.Sprintf("https://keys.pub/user/%s@%s", usr.Name, usr.Service)
	return Request(ctx, client, url, nil)
}

func (s *kpUser) Verify(ctx context.Context, b []byte, usr *user.User) (user.Status, string, error) {
	msg, err := s.checkContent(usr, b)
	if err != nil {
		return user.StatusContentInvalid, "", err
	}
	return user.FindVerify(usr, msg, false)
}

func (s *kpUser) checkContent(usr *user.User, b []byte) ([]byte, error) {
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

	return []byte(us.Statement), nil
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
