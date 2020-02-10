package keys

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

// UserResult is result of a user result.
type UserResult struct {
	Err        string     `json:"err,omitempty"`
	Status     UserStatus `json:"status"`
	Timestamp  TimeMs     `json:"ts"`
	User       *User      `json:"user"`
	VerifiedAt TimeMs     `json:"vts"`
}

func (r UserResult) String() string {
	if r.Status == UserStatusOK {
		return fmt.Sprintf("%s:%s(%d)", r.Status, r.User, r.VerifiedAt)
	}
	return fmt.Sprintf("%s:%s;err=%s", r.Status, r.User, r.Err)
}

type keyDocument struct {
	KID        ID          `json:"kid"`
	UserResult *UserResult `json:"result,omitempty"`
}

// UserStore is the environment for user results.
type UserStore struct {
	dst             DocumentStore
	scs             SigchainStore
	req             Requestor
	nowFn           func() time.Time
	enabledServices *StringSet
}

// NewUserStore creates UserStore.
func NewUserStore(dst DocumentStore, scs SigchainStore, services []string, req Requestor, nowFn func() time.Time) (*UserStore, error) {
	for _, service := range services {
		if err := validateServiceSupported(service); err != nil {
			return nil, err
		}
	}
	return &UserStore{
		dst:             dst,
		scs:             scs,
		enabledServices: NewStringSet(services...),
		nowFn:           nowFn,
		req:             req,
	}, nil
}

// Now returns current time.
func (u *UserStore) Now() time.Time {
	return u.nowFn()
}

// Requestor ...
func (u *UserStore) Requestor() Requestor {
	return u.req
}

// Update index for sigchain KID.
func (u *UserStore) Update(ctx context.Context, kid ID) (*UserResult, error) {
	logger.Infof("Updating user index for %s", kid)
	sc, err := u.scs.Sigchain(kid)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, nil
	}

	logger.Infof("Checking users %s", kid)
	result, err := u.checkSigchain(ctx, sc)
	if err != nil {
		return nil, err
	}

	keyDoc := &keyDocument{
		KID:        kid,
		UserResult: result,
	}

	logger.Infof("Indexing %s: %+v", keyDoc.KID, keyDoc.UserResult)
	if err := u.index(ctx, keyDoc); err != nil {
		return nil, err
	}

	return result, nil
}

func userResultsStrings(res []*UserResult) []string {
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.String())
	}
	return out
}

func (u *UserStore) checkSigchain(ctx context.Context, sc *Sigchain) (*UserResult, error) {
	user, err := sc.User()
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	result, err := u.result(ctx, sc.ID())
	if err != nil {
		return nil, err
	}
	if result == nil {
		result = &UserResult{
			User: user,
		}
	}
	if err := u.updateResult(ctx, result, sc.PublicKey()); err != nil {
		return nil, err
	}
	return result, nil
}

// Check a user. Doesn't index result.
func (u *UserStore) Check(ctx context.Context, user *User, spk SigchainPublicKey) (*UserResult, error) {
	res := &UserResult{
		User: user,
	}
	if err := u.updateResult(ctx, res, spk); err != nil {
		return nil, err
	}
	return res, nil
}

func (u *UserStore) updateResult(ctx context.Context, result *UserResult, spk SigchainPublicKey) error {
	if result == nil {
		return errors.Errorf("no user specified")
	}

	result.Timestamp = TimeToMillis(u.Now())

	logger.Infof("Resulting user %s", result.User.String())
	ur, err := url.Parse(result.User.URL)
	if err != nil {
		logger.Warningf("Failed to parse user url: %s", err)
		result.Err = err.Error()
		result.Status = UserStatusFailure
		return nil
	}
	logger.Infof("Requesting %s", ur)
	body, err := u.req.RequestURL(ctx, ur)
	if err != nil {
		if errHTTP, ok := errors.Cause(err).(ErrHTTP); ok && errHTTP.StatusCode == 404 {
			result.Err = err.Error()
			result.Status = UserStatusResourceNotFound
			return nil
		}
		result.Err = err.Error()
		result.Status = UserStatusConnFailure
		return nil
	}

	msg, _ := findSaltpack(string(body), true)
	if msg == "" {
		logger.Warningf("User statement content not found")
		result.Err = "user signed message content not found"
		result.Status = UserStatusContentNotFound
		return nil
	}

	verifyMsg := fmt.Sprintf("BEGIN MESSAGE.\n%s\nEND MESSAGE.", msg)
	_, err = VerifyUser(verifyMsg, spk, result.User)
	if err != nil {
		logger.Warningf("Failed to verify statement: %s", err)
		result.Err = err.Error()
		result.Status = UserStatusFailure
		return nil
	}

	logger.Infof("Verified %s", result.User.KID)
	result.Err = ""
	result.Status = UserStatusOK
	result.VerifiedAt = TimeToMillis(u.Now())
	return nil
}

// ValidateStatement returns error if statement is not a valid user statement.
func (u *UserStore) ValidateStatement(st *Statement) error {
	if st.Type != "user" {
		return errors.Errorf("invalid user statement: %s != %s", st.Type, "user")
	}
	var user User
	if err := json.Unmarshal(st.Data, &user); err != nil {
		return err
	}
	if err := u.validate(&user); err != nil {
		return err
	}
	return nil
}

// Get user result for KID.
// Retrieves cached result. If Update(kid) has not been called or there is no
// user statement, this will return nil.
func (u *UserStore) Get(ctx context.Context, kid ID) (*UserResult, error) {
	res, err := u.get(ctx, indexKID, kid.String())
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.UserResult, nil
}

// User result for user name@service.
func (u *UserStore) User(ctx context.Context, user string) (*UserResult, error) {
	res, err := u.get(ctx, indexUser, user)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.UserResult, nil
}

func (u *UserStore) get(ctx context.Context, index string, val string) (*keyDocument, error) {
	if val == "" {
		return nil, errors.Errorf("empty value")
	}
	path := Path(index, val)
	doc, err := u.dst.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	var keyDoc keyDocument
	if err := json.Unmarshal(doc.Data, &keyDoc); err != nil {
		return nil, err
	}
	return &keyDoc, nil
}

func (u *UserStore) result(ctx context.Context, kid ID) (*UserResult, error) {
	doc, err := u.get(ctx, indexKID, kid.String())
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	return doc.UserResult, nil
}

func (u *UserStore) removeUser(ctx context.Context, user *User) error {
	name := fmt.Sprintf("%s@%s", user.Name, user.Service)
	namePath := Path(indexUser, name)
	logger.Infof("Removing user %s: %s", user.KID, name)
	if _, err := u.dst.Delete(ctx, namePath); err != nil {
		return err
	}
	return nil
}

const indexKID = "kid"
const indexUser = "user"

func (u *UserStore) index(ctx context.Context, keyDoc *keyDocument) error {
	// Remove existing if different
	existing, err := u.get(ctx, indexKID, keyDoc.KID.String())
	if err != nil {
		return err
	}
	if existing != nil && existing.UserResult != nil && existing.UserResult.User != nil {
		if keyDoc.UserResult == nil || keyDoc.UserResult.User == nil ||
			(existing.UserResult.User.Name != keyDoc.UserResult.User.Name &&
				existing.UserResult.User.Service != keyDoc.UserResult.User.Service) {
			if err := u.removeUser(ctx, existing.UserResult.User); err != nil {
				return err
			}
		}
	}

	data, err := json.Marshal(keyDoc)
	if err != nil {
		return err
	}
	logger.Debugf("Data to index: %s", string(data))

	kidPath := Path(indexKID, keyDoc.KID.String())
	logger.Infof("Indexing kid %s", kidPath)
	if err := u.dst.Set(ctx, kidPath, data); err != nil {
		return err
	}

	if keyDoc.UserResult != nil {
		index := false
		if keyDoc.UserResult.VerifiedAt == 0 {
			logger.Errorf("Never verified user result in indexing: %v", keyDoc.UserResult)
		} else {
			switch keyDoc.UserResult.Status {
			// Index result if status ok, or a transient error
			case UserStatusOK, UserStatusConnFailure:
				index = true
			}
		}

		if index {
			name := indexName(keyDoc.UserResult.User)
			namePath := Path(indexUser, name)
			logger.Infof("Indexing user result %s %s", namePath, keyDoc.UserResult.User.KID)
			if err := u.dst.Set(ctx, namePath, data); err != nil {
				return err
			}
		} else {
			logger.Infof("Removing failed user %s", keyDoc.UserResult.User)
			if err := u.removeUser(ctx, keyDoc.UserResult.User); err != nil {
				return err
			}
		}
	}

	return nil
}

func indexName(user *User) string {
	return fmt.Sprintf("%s@%s", user.Name, user.Service)
}

// Expired returns KIDs that haven't been checked in a duration.
func (u *UserStore) Expired(ctx context.Context, dt time.Duration) ([]ID, error) {
	iter, err := u.dst.Documents(context.TODO(), indexKID, nil)
	if err != nil {
		return nil, err
	}
	kids := make([]ID, 0, 100)
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		var keyDoc keyDocument
		if err := json.Unmarshal(doc.Data, &keyDoc); err != nil {
			return nil, err
		}
		if keyDoc.UserResult != nil {
			ts := TimeFromMillis(keyDoc.UserResult.Timestamp)
			if ts.IsZero() || u.Now().Sub(ts) > dt {
				kids = append(kids, keyDoc.UserResult.User.KID)
				break
			}
		}
	}
	iter.Release()

	return kids, nil
}
