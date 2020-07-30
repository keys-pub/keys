package user

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
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

type keyDocument struct {
	KID    keys.ID `json:"kid"`
	Result *Result `json:"result,omitempty"`
}

// Store is the environment for user results.
type Store struct {
	ds    docs.Documents
	scs   keys.SigchainStore
	req   request.Requestor
	clock tsutil.Clock
}

// NewStore creates Store.
func NewStore(ds docs.Documents, scs keys.SigchainStore, req request.Requestor, clock tsutil.Clock) (*Store, error) {
	return &Store{
		ds:    ds,
		scs:   scs,
		req:   req,
		clock: clock,
	}, nil
}

// Requestor ...
func (u *Store) Requestor() request.Requestor {
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

// CheckSigchain looks for user in a Sigchain and updates the current result in the Store.
func (u *Store) CheckSigchain(ctx context.Context, sc *keys.Sigchain) (*Result, error) {
	usr, err := FindInSigchain(sc)
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
		result = &Result{}
	}
	// Update result user (in case user changed)
	result.User = usr

	if usr.KID != sc.KID() {
		return nil, errors.Errorf("user sigchain kid mismatch %s != %s", usr.KID, sc.KID())
	}

	updateResult(ctx, u.req, usr, result, u.clock.Now())

	return result, nil
}

// RequestVerify a user. Doesn't index result.
func (u *Store) RequestVerify(ctx context.Context, usr *User) *Result {
	return RequestVerify(ctx, u.req, usr, u.clock.Now())
}

// ValidateStatement returns error if statement is not a valid user statement.
func ValidateStatement(st *keys.Statement) error {
	if st.Type != "user" {
		return errors.Errorf("invalid user statement: %s != %s", st.Type, "user")
	}
	var user User
	if err := json.Unmarshal(st.Data, &user); err != nil {
		return err
	}
	if err := Validate(&user); err != nil {
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
	path := docs.Path(index, val)
	doc, err := u.ds.Get(ctx, path)
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
	namePath := docs.Path(indexUser, indexName(user))
	logger.Infof("Removing user %s: %s", user.KID, namePath)
	if _, err := u.ds.Delete(ctx, namePath); err != nil {
		return err
	}
	return nil
}

// indexKID is collection for key identifiers.
const indexKID = "kid"

// indexUser is collection for user@service.
const indexUser = "user"

// indexRKL is collection for reverse key lookups.
const indexRKL = "rkl"

// TODO: Remove document from indexes if failed for a long time?

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

	// Index for kid
	kidPath := docs.Path(indexKID, keyDoc.KID.String())
	logger.Infof("Indexing kid %s", kidPath)
	if err := u.ds.Set(ctx, kidPath, data); err != nil {
		return err
	}

	// Index for rkl
	rk, err := keys.Convert(keyDoc.KID, keys.X25519Public)
	if err != nil {
		return err
	}
	rklPath := docs.Path(indexRKL, rk.ID())
	if err := u.ds.Set(ctx, rklPath, []byte(keyDoc.KID.String())); err != nil {
		return err
	}

	// Index for user
	if keyDoc.Result != nil {
		index := false
		if keyDoc.Result.VerifiedAt == 0 {
			logger.Warningf("Never verified user result in indexing: %v", keyDoc.Result)
		} else {
			switch keyDoc.Result.Status {
			// Index result if status ok, or a transient error
			case StatusOK, StatusConnFailure:
				index = true
			}
		}

		if index {
			namePath := docs.Path(indexUser, indexName(keyDoc.Result.User))
			logger.Infof("Indexing user result %s %s", namePath, keyDoc.Result.User.KID)
			if err := u.ds.Set(ctx, namePath, data); err != nil {
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

func (u *Store) lookupRelated(ctx context.Context, kid keys.ID) (keys.ID, error) {
	path := docs.Path(indexRKL, kid.String())
	doc, err := u.ds.Get(ctx, path)
	if err != nil {
		return "", err
	}
	if doc == nil {
		return "", nil
	}
	rkid, err := keys.ParseID(string(doc.Data))
	if err != nil {
		return "", err
	}
	return rkid, nil
}

// Status returns KIDs that match a status.
func (u *Store) Status(ctx context.Context, st Status) ([]keys.ID, error) {
	iter, err := u.ds.DocumentIterator(context.TODO(), indexKID)
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
			}
		}
	}
	iter.Release()

	return kids, nil
}

// Expired returns KIDs that haven't been checked in a duration.
func (u *Store) Expired(ctx context.Context, dt time.Duration, maxAge time.Duration) ([]keys.ID, error) {
	iter, err := u.ds.DocumentIterator(context.TODO(), indexKID)
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
			ts := tsutil.ConvertMillis(keyDoc.Result.Timestamp)

			// If verifiedAt age is too old skip it
			vts := tsutil.ConvertMillis(keyDoc.Result.VerifiedAt)
			if !vts.IsZero() && u.clock.Now().Sub(vts) > maxAge {
				continue
			}

			if ts.IsZero() || u.clock.Now().Sub(ts) > dt {
				kids = append(kids, keyDoc.Result.User.KID)
			}
		}
	}
	iter.Release()

	return kids, nil
}

// CheckForExisting returns key ID of exsiting user in sigchain different from this
// sigchain key.
func (u *Store) CheckForExisting(ctx context.Context, sc *keys.Sigchain) (keys.ID, error) {
	usr, err := FindInSigchain(sc)
	if err != nil {
		return "", err
	}
	if usr != nil {
		logger.Debugf("Checking for existing user %s...", usr.ID())
		q := usr.ID()
		results, err := u.Search(ctx, &SearchRequest{Query: q})
		if err != nil {
			return "", err
		}
		if len(results) > 0 {
			for _, res := range results {
				logger.Debugf("Found user %s with %s", usr.ID(), res.KID)
				if res.KID != sc.KID() {
					return res.KID, nil
				}
			}
		}
	}
	return "", nil
}

// KIDs returns all key ids in the user store.
func (u *Store) KIDs(ctx context.Context) ([]keys.ID, error) {
	iter, err := u.ds.DocumentIterator(context.TODO(), indexKID)
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

		// We could parse the path for the kid instead of unmarshalling.
		var keyDoc keyDocument
		if err := json.Unmarshal(doc.Data, &keyDoc); err != nil {
			return nil, err
		}
		if keyDoc.Result != nil {
			kids = append(kids, keyDoc.Result.User.KID)
		}
	}
	iter.Release()

	return kids, nil
}
