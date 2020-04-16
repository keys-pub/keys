package user

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/ds"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/link"
	"github.com/keys-pub/keys/util"
	"github.com/pkg/errors"
)

// Result describes the status of a User.
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
	ts := util.TimeFromMillis(r.Timestamp)
	return (ts.IsZero() || now.Sub(ts) > dt)
}

// IsVerifyExpired returns true if result VerifiedAt is older than dt.
func (r Result) IsVerifyExpired(now time.Time, dt time.Duration) bool {
	ts := util.TimeFromMillis(r.VerifiedAt)
	return (ts.IsZero() || now.Sub(ts) > dt)
}

type keyDocument struct {
	KID    keys.ID `json:"kid"`
	Result *Result `json:"result,omitempty"`
}

// Store is the environment for user results.
type Store struct {
	dst   ds.DocumentStore
	scs   keys.SigchainStore
	req   util.Requestor
	nowFn func() time.Time
}

// NewStore creates Store.
func NewStore(dst ds.DocumentStore, scs keys.SigchainStore, req util.Requestor, nowFn func() time.Time) (*Store, error) {
	return &Store{
		dst:   dst,
		scs:   scs,
		nowFn: nowFn,
		req:   req,
	}, nil
}

// Now returns current time.
func (u *Store) Now() time.Time {
	return u.nowFn()
}

// Requestor ...
func (u *Store) Requestor() util.Requestor {
	return u.req
}

// Update index for sigchain KID.
func (u *Store) Update(ctx context.Context, kid keys.ID) (*Result, error) {
	logger.Infof("Updating user index for %s", kid)
	sc, err := u.scs.Sigchain(kid)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, nil
	}

	logger.Infof("Checking users %s", kid)
	result, err := u.CheckSigchain(ctx, sc)
	if err != nil {
		return nil, err
	}

	keyDoc := &keyDocument{
		KID:    kid,
		Result: result,
	}

	logger.Infof("Indexing %s: %+v", keyDoc.KID, keyDoc.Result)
	if err := u.index(ctx, keyDoc); err != nil {
		return nil, err
	}

	return result, nil
}

// CheckSigchain looks for user in a Sigchain.
func (u *Store) CheckSigchain(ctx context.Context, sc *keys.Sigchain) (*Result, error) {
	usr, err := ResolveSigchain(sc)
	if err != nil {
		return nil, err
	}
	if usr == nil {
		return nil, nil
	}
	result, err := u.result(ctx, sc.KID())
	if err != nil {
		return nil, err
	}
	if result == nil {
		result = &Result{
			User: usr,
		}
	}

	u.updateResult(ctx, result, sc.KID())

	return result, nil
}

// Check a user. Doesn't index result.
func (u *Store) Check(ctx context.Context, user *User, kid keys.ID) (*Result, error) {
	res := &Result{
		User: user,
	}
	u.updateResult(ctx, res, kid)
	return res, nil
}

// updateResult updates the specified result.
func (u *Store) updateResult(ctx context.Context, result *Result, kid keys.ID) {
	if result == nil {
		panic("no user result specified")
	}
	logger.Infof("Update user %s", result.User.String())

	ur, err := url.Parse(result.User.URL)
	if err != nil {
		result.Err = err.Error()
		result.Status = StatusFailure
		return
	}

	service, err := link.NewService(result.User.Service)
	if err != nil {
		result.Err = err.Error()
		result.Status = StatusFailure
		return
	}
	ur, err = service.ValidateURL(result.User.Name, ur)
	if err != nil {
		result.Err = err.Error()
		result.Status = StatusFailure
		return
	}

	result.Timestamp = util.TimeToMillis(u.Now())

	logger.Infof("Requesting %s", ur)
	body, err := u.req.RequestURL(ctx, ur)
	if err != nil {
		logger.Warningf("Request failed: %v", err)
		if errHTTP, ok := errors.Cause(err).(util.ErrHTTP); ok && errHTTP.StatusCode == 404 {
			result.Err = err.Error()
			result.Status = StatusResourceNotFound
			return
		}
		result.Err = err.Error()
		result.Status = StatusConnFailure
		return
	}

	b, err := service.CheckContent(result.User.Name, body)
	if err != nil {
		logger.Warningf("Failed to check content: %s", err)
		result.Err = err.Error()
		result.Status = StatusContentInvalid
		return
	}

	st, err := VerifyContent(b, result, kid)
	if err != nil {
		logger.Warningf("Failed to verify content: %s", err)
		result.Err = err.Error()
		result.Status = st
		return
	}

	logger.Infof("Verified %s", result.User.KID)
	result.Err = ""
	result.Status = StatusOK
	result.VerifiedAt = util.TimeToMillis(u.Now())
}

// VerifyContent checks content.
func VerifyContent(b []byte, result *Result, kid keys.ID) (Status, error) {
	msg, _ := encoding.FindSaltpack(string(b), true)
	if msg == "" {
		logger.Warningf("User statement content not found")
		return StatusContentNotFound, errors.Errorf("user signed message content not found")
	}

	verifyMsg := fmt.Sprintf("BEGIN MESSAGE.\n%s\nEND MESSAGE.", msg)
	if _, err := Verify(verifyMsg, kid, result.User); err != nil {
		logger.Warningf("Failed to verify statement: %s", err)
		return StatusStatementInvalid, err
	}

	return StatusOK, nil
}

// ValidateStatement returns error if statement is not a valid user statement.
func (u *Store) ValidateStatement(st *keys.Statement) error {
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
func (u *Store) Get(ctx context.Context, kid keys.ID) (*Result, error) {
	res, err := u.get(ctx, indexKID, kid.String())
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.Result, nil
}

// User result for user name@service.
// Retrieves cached result. If Update(kid) has not been called or there is no
// user statement, this will return nil.
func (u *Store) User(ctx context.Context, user string) (*Result, error) {
	res, err := u.get(ctx, indexUser, user)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.Result, nil
}

func (u *Store) get(ctx context.Context, index string, val string) (*keyDocument, error) {
	if val == "" {
		return nil, errors.Errorf("empty value")
	}
	path := ds.Path(index, val)
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

func (u *Store) result(ctx context.Context, kid keys.ID) (*Result, error) {
	doc, err := u.get(ctx, indexKID, kid.String())
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	return doc.Result, nil
}

func (u *Store) removeUser(ctx context.Context, user *User) error {
	name := fmt.Sprintf("%s@%s", user.Name, user.Service)
	namePath := ds.Path(indexUser, name)
	logger.Infof("Removing user %s: %s", user.KID, name)
	if _, err := u.dst.Delete(ctx, namePath); err != nil {
		return err
	}
	return nil
}

const indexKID = "kid"
const indexUser = "user"

func (u *Store) index(ctx context.Context, keyDoc *keyDocument) error {
	// Remove existing if different
	existing, err := u.get(ctx, indexKID, keyDoc.KID.String())
	if err != nil {
		return err
	}
	if existing != nil && existing.Result != nil && existing.Result.User != nil {
		if keyDoc.Result == nil || keyDoc.Result.User == nil ||
			(existing.Result.User.Name != keyDoc.Result.User.Name &&
				existing.Result.User.Service != keyDoc.Result.User.Service) {
			if err := u.removeUser(ctx, existing.Result.User); err != nil {
				return err
			}
		}
	}

	data, err := json.Marshal(keyDoc)
	if err != nil {
		return err
	}
	logger.Debugf("Data to index: %s", string(data))

	kidPath := ds.Path(indexKID, keyDoc.KID.String())
	logger.Infof("Indexing kid %s", kidPath)
	if err := u.dst.Set(ctx, kidPath, data); err != nil {
		return err
	}

	if keyDoc.Result != nil {
		index := false
		if keyDoc.Result.VerifiedAt == 0 {
			logger.Errorf("Never verified user result in indexing: %v", keyDoc.Result)
		} else {
			switch keyDoc.Result.Status {
			// Index result if status ok, or a transient error
			case StatusOK, StatusConnFailure:
				index = true
			}
		}

		if index {
			name := indexName(keyDoc.Result.User)
			namePath := ds.Path(indexUser, name)
			logger.Infof("Indexing user result %s %s", namePath, keyDoc.Result.User.KID)
			if err := u.dst.Set(ctx, namePath, data); err != nil {
				return err
			}
		} else {
			logger.Infof("Removing failed user %s", keyDoc.Result.User)
			if err := u.removeUser(ctx, keyDoc.Result.User); err != nil {
				return err
			}
		}
	}

	return nil
}

func indexName(user *User) string {
	return fmt.Sprintf("%s@%s", user.Name, user.Service)
}

// Status returns KIDs that match a status.
func (u *Store) Status(ctx context.Context, st Status) ([]keys.ID, error) {
	iter, err := u.dst.Documents(context.TODO(), indexKID, nil)
	if err != nil {
		return nil, err
	}
	kids := make([]keys.ID, 0, 100)
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
		if keyDoc.Result != nil {
			if keyDoc.Result.Status == st {
				kids = append(kids, keyDoc.Result.User.KID)
				break
			}
		}
	}
	iter.Release()

	return kids, nil
}

// Expired returns KIDs that haven't been checked in a duration.
func (u *Store) Expired(ctx context.Context, dt time.Duration) ([]keys.ID, error) {
	iter, err := u.dst.Documents(context.TODO(), indexKID, nil)
	if err != nil {
		return nil, err
	}
	kids := make([]keys.ID, 0, 100)
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
		if keyDoc.Result != nil {
			ts := util.TimeFromMillis(keyDoc.Result.Timestamp)

			if ts.IsZero() || u.Now().Sub(ts) > dt {
				kids = append(kids, keyDoc.Result.User.KID)
				break
			}
		}
	}
	iter.Release()

	return kids, nil
}
