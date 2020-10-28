package users

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/request"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/keys/user"
	"github.com/pkg/errors"
)

// Users keeps track of sigchain user links.
type Users struct {
	ds    docs.Documents
	scs   *keys.Sigchains
	req   request.Requestor
	clock tsutil.Clock
}

type keyDocument struct {
	KID    keys.ID      `json:"kid"`
	Result *user.Result `json:"result,omitempty"`
}

// New creates Users lookup.
func New(ds docs.Documents, scs *keys.Sigchains, opt ...Option) *Users {
	opts := newOptions(opt...)
	req := opts.Req
	if req == nil {
		req = request.NewHTTPRequestor()
	}
	clock := opts.Clock
	if clock == nil {
		clock = tsutil.NewClock()
	}
	return &Users{
		ds:    ds,
		scs:   scs,
		req:   req,
		clock: clock,
	}
}

// Requestor ...
func (u *Users) Requestor() request.Requestor {
	return u.req
}

// Update index for sigchain KID.
func (u *Users) Update(ctx context.Context, kid keys.ID) (*user.Result, error) {
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

// CheckSigchain looks for user in a Sigchain and creates a result or updates
// the current result.
func (u *Users) CheckSigchain(ctx context.Context, sc *keys.Sigchain) (*user.Result, error) {
	usr, err := user.FindInSigchain(sc)
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
		result = &user.Result{}
	}
	// Set or update user (in case user changed)
	result.User = usr

	if usr.KID != sc.KID() {
		return nil, errors.Errorf("user sigchain kid mismatch %s != %s", usr.KID, sc.KID())
	}

	result.Update(ctx, u.req, u.clock.Now())

	return result, nil
}

// RequestVerify requests and verifies a user. Doesn't index result.
func (u *Users) RequestVerify(ctx context.Context, usr *user.User) *user.Result {
	return usr.RequestVerify(ctx, user.Requestor(u.req), user.Clock(u.clock))
}

// ValidateStatement returns error if statement is not a valid user statement.
func ValidateStatement(st *keys.Statement) error {
	if st.Type != "user" {
		return errors.Errorf("invalid user statement: %s != %s", st.Type, "user")
	}
	var usr user.User
	if err := json.Unmarshal(st.Data, &usr); err != nil {
		return err
	}
	if err := usr.Validate(); err != nil {
		return err
	}
	return nil
}

// Get user result for KID.
// Retrieves cached result. If Update(kid) has not been called or there is no
// user statement, this will return nil.
func (u *Users) Get(ctx context.Context, kid keys.ID) (*user.Result, error) {
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
func (u *Users) User(ctx context.Context, user string) (*user.Result, error) {
	keyDoc, err := u.get(ctx, indexUser, user)
	if err != nil {
		return nil, err
	}
	if keyDoc == nil {
		return nil, nil
	}
	return keyDoc.Result, nil
}

func (u *Users) get(ctx context.Context, index string, val string) (*keyDocument, error) {
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

func (u *Users) result(ctx context.Context, kid keys.ID) (*user.Result, error) {
	doc, err := u.get(ctx, indexKID, kid.String())
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	return doc.Result, nil
}

func (u *Users) indexUser(ctx context.Context, user *user.User, data []byte, skipSearch bool) error {
	logger.Infof("Indexing user %s %s", user.ID, user.KID)
	userPath := docs.Path(indexUser, indexUserKey(user.Service, user.Name))
	if err := u.ds.Set(ctx, userPath, data); err != nil {
		return err
	}
	servicePath := docs.Path(indexService, indexServiceKey(user.Service, user.Name))
	if err := u.ds.Set(ctx, servicePath, data); err != nil {
		return err
	}
	if !skipSearch {
		searchPath := docs.Path(indexSearch, indexUserKey(user.Service, user.Name))
		if err := u.ds.Set(ctx, searchPath, data); err != nil {
			return err
		}
	}
	return nil
}

func (u *Users) unindexUser(ctx context.Context, user *user.User) error {
	logger.Infof("Removing user %s: %s", user.KID, indexUserKey(user.Service, user.Name))

	userPath := docs.Path(indexUser, indexUserKey(user.Service, user.Name))
	if _, err := u.ds.Delete(ctx, userPath); err != nil {
		return err
	}
	servicePath := docs.Path(indexService, indexServiceKey(user.Service, user.Name))
	if _, err := u.ds.Delete(ctx, servicePath); err != nil {
		return err
	}
	searchPath := docs.Path(indexSearch, indexUserKey(user.Service, user.Name))
	if _, err := u.ds.Delete(ctx, searchPath); err != nil {
		return err
	}
	return nil
}

// indexKID is collection for key identifiers.
const indexKID = "kid"

// indexUser is collection for user@service.
const indexUser = "user"

// indexUser is collection for user@service for search.
const indexSearch = "search"

// indexService is collection for user by service.
const indexService = "service"

// TODO: Remove document from indexes if failed for a long time?

func isNewResultDifferent(new *user.Result, old *user.Result) bool {
	if old != nil && (new == nil || new.User == nil) {
		return true
	}
	if old != nil && new != nil && new.User != nil && old.User != nil && new.User.ID() != old.User.ID() {
		return true
	}
	return false
}

func (u *Users) index(ctx context.Context, keyDoc *keyDocument) error {
	// Remove existing if different.
	existing, err := u.get(ctx, indexKID, keyDoc.KID.String())
	if err != nil {
		return err
	}
	if existing != nil && isNewResultDifferent(keyDoc.Result, existing.Result) {
		if err := u.unindexUser(ctx, existing.Result.User); err != nil {
			return err
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

	// Index for user
	if keyDoc.Result != nil {
		index := false
		if keyDoc.Result.VerifiedAt == 0 {
			logger.Warningf("Never verified user result in indexing: %v", keyDoc.Result)
		} else {
			switch keyDoc.Result.Status {
			// Index if status ok, or a recent connection failure (< 2 days).
			case user.StatusOK:
				index = true
			case user.StatusConnFailure:
				// If connection failure is recent, still index.
				if u.clock.Now().Sub(tsutil.ConvertMillis(keyDoc.Result.VerifiedAt)) < time.Hour*24*2 {
					index = true
				}
			}
		}

		if index {
			skipSearch := false
			switch keyDoc.Result.User.Service {
			case "echo":
				skipSearch = true
			}
			if err := u.indexUser(ctx, keyDoc.Result.User, data, skipSearch); err != nil {
				return err
			}
		} else {
			if err := u.unindexUser(ctx, keyDoc.Result.User); err != nil {
				return err
			}
		}
	}

	return nil
}

func indexUserKey(service string, name string) string {
	return fmt.Sprintf("%s@%s", name, service)
}

func indexServiceKey(service string, name string) string {
	return fmt.Sprintf("%s@%s", service, name)
}

// Find user result for KID.
// Will also search for related keys.
func (u *Users) Find(ctx context.Context, kid keys.ID) (*user.Result, error) {
	res, err := u.Get(ctx, kid)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil
	}
	rkid, err := u.scs.Lookup(kid)
	if err != nil {
		return nil, err
	}
	if rkid == "" {
		return nil, nil
	}
	return u.Get(ctx, rkid)
}

// Status returns KIDs that match a status.
func (u *Users) Status(ctx context.Context, st user.Status) ([]keys.ID, error) {
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
func (u *Users) Expired(ctx context.Context, dt time.Duration, maxAge time.Duration) ([]keys.ID, error) {
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
func (u *Users) CheckForExisting(ctx context.Context, sc *keys.Sigchain) (keys.ID, error) {
	usr, err := user.FindInSigchain(sc)
	if err != nil {
		return "", err
	}
	if usr != nil {
		logger.Debugf("Checking for existing user %s...", usr.ID())
		res, err := u.User(ctx, usr.ID())
		if err != nil {
			return "", err
		}
		if res != nil {
			logger.Debugf("Found user %s with %s", usr.ID(), res.User.KID)
			if res.User.KID != sc.KID() {
				return res.User.KID, nil
			}
		}
	}
	return "", nil
}

// KIDs returns all key ids in the user store.
func (u *Users) KIDs(ctx context.Context) ([]keys.ID, error) {
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