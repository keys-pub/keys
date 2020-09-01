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

// Users keeps track of sigchain user links.
type Users struct {
	ds    docs.Documents
	scs   *keys.Sigchains
	req   request.Requestor
	clock tsutil.Clock
}

// NewUsers creates Users.
func NewUsers(ds docs.Documents, scs *keys.Sigchains, opt ...UsersOption) *Users {
	opts := newUserOptions(opt...)
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
func (u *Users) Update(ctx context.Context, kid keys.ID) ([]*Result, error) {
	logger.Infof("Updating user index for %s", kid)
	sc, err := u.scs.Sigchain(kid)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, nil
	}

	logger.Infof("Checking users for %s", kid)
	results, err := u.CheckSigchain(ctx, sc)
	if err != nil {
		return nil, err
	}

	keyDoc := &keyDocument{
		KID:     kid,
		Results: results,
	}
	logger.Infof("Indexing %s: %+v", keyDoc.KID, keyDoc.Results)
	if err := u.index(ctx, keyDoc); err != nil {
		return nil, err
	}

	return results, nil
}

func findResult(usr *User, results []*Result) *Result {
	for _, res := range results {
		if res.User.ID() == usr.ID() {
			return res
		}
	}
	return nil
}

func fillResult(usr *User, results []*Result) *Result {
	res := findResult(usr, results)
	if res != nil {
		res.User = usr
		return res
	}
	return &Result{
		User: usr,
	}
}

// CheckSigchain looks for users in a Sigchain and updates results.
func (u *Users) CheckSigchain(ctx context.Context, sc *keys.Sigchain) ([]*Result, error) {
	users, err := FindInSigchain(sc)
	if err != nil {
		return nil, err
	}
	results, err := u.results(ctx, sc.KID())
	if err != nil {
		return nil, err
	}

	out := []*Result{}
	for _, usr := range users {
		result := fillResult(usr, results)
		updateResult(ctx, u.req, result, u.clock.Now())
		out = append(out, result)
	}

	return out, nil
}

// RequestVerify a user. Doesn't index result.
func (u *Users) RequestVerify(ctx context.Context, usr *User) *Result {
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

// Get user results for KID.
// Retrieves cached results, if Update(kid) has not been called will return no results.
func (u *Users) Get(ctx context.Context, kid keys.ID) ([]*Result, error) {
	res, err := u.getKey(ctx, indexKID, kid.String())
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	return res.Results, nil
}

// User result for user name@service.
// Retrieves cached results, if Update(kid) has not been called it will return no results.
func (u *Users) User(ctx context.Context, user string) (*Result, error) {
	userDoc, err := u.getUser(ctx, indexUser, user)
	if err != nil {
		return nil, err
	}
	if userDoc == nil {
		return nil, nil
	}
	return userDoc.Result, nil
}

func (u *Users) getKey(ctx context.Context, index string, val string) (*keyDocument, error) {
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

func (u *Users) getUser(ctx context.Context, index string, val string) (*userDocument, error) {
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
	var userDoc userDocument
	if err := json.Unmarshal(doc.Data, &userDoc); err != nil {
		return nil, err
	}
	return &userDoc, nil
}

func (u *Users) results(ctx context.Context, kid keys.ID) ([]*Result, error) {
	doc, err := u.getKey(ctx, indexKID, kid.String())
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	return doc.Results, nil
}

func (u *Users) indexUser(ctx context.Context, result *Result, skipSearch bool) error {
	user := result.User
	data, err := json.Marshal(&userDocument{KID: user.KID, Result: result})
	if err != nil {
		return err
	}
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

func (u *Users) unindexUser(ctx context.Context, user *User) error {
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

func (u *Users) unindexRemoved(ctx context.Context, keyDoc *keyDocument) error {
	existing, err := u.getKey(ctx, indexKID, keyDoc.KID.String())
	if err != nil {
		return err
	}
	if existing == nil {
		return nil
	}
	for _, e := range existing.Results {
		// TODO: Change to keyDoc.Results after re-index
		found := findResult(e.User, keyDoc.resultsForCompatibility())
		if found == nil {
			if err := u.unindexUser(ctx, e.User); err != nil {
				return err
			}
		}
	}
	return nil
}

func (u *Users) index(ctx context.Context, keyDoc *keyDocument) error {
	if err := u.unindexRemoved(ctx, keyDoc); err != nil {
		return err
	}

	// Index for kid
	kidPath := docs.Path(indexKID, keyDoc.KID.String())
	logger.Infof("Indexing kid %s", kidPath)
	data, err := json.Marshal(keyDoc)
	if err != nil {
		return err
	}
	if err := u.ds.Set(ctx, kidPath, data); err != nil {
		return err
	}

	// Index for user
	for _, result := range keyDoc.Results {
		index := false
		if result.VerifiedAt == 0 {
			logger.Warningf("Never verified user result in indexing: %v", result)
		} else {
			switch result.Status {
			// Index result if status ok, or a transient error
			case StatusOK, StatusConnFailure:
				index = true
			}
		}

		if index {
			skipSearch := false
			switch result.User.Service {
			case "echo":
				skipSearch = true
			}
			if err := u.indexUser(ctx, result, skipSearch); err != nil {
				return err
			}
		} else {
			if err := u.unindexUser(ctx, result.User); err != nil {
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

// Find user results for KID.
// Will also search for related keys.
func (u *Users) Find(ctx context.Context, kid keys.ID) ([]*Result, error) {
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

// Status returns keys that have a result status.
// For example, if you want to get all keys that have a StatusConnFailure.
func (u *Users) Status(ctx context.Context, st Status) ([]keys.ID, error) {
	iter, err := u.ds.DocumentIterator(context.TODO(), indexKID)
	if err != nil {
		return nil, err
	}
	out := make([]keys.ID, 0, 100)
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
		// TODO: Change to keyDoc.Results after re-index
		for _, res := range keyDoc.resultsForCompatibility() {
			if res.Status == st {
				out = append(out, keyDoc.KID)
				break
			}
		}
	}
	iter.Release()

	return out, nil
}

// Expired returns keys that have a result that hasn't been checked in a duration.
func (u *Users) Expired(ctx context.Context, dt time.Duration, maxAge time.Duration) ([]keys.ID, error) {
	iter, err := u.ds.DocumentIterator(context.TODO(), indexKID)
	if err != nil {
		return nil, err
	}
	out := make([]keys.ID, 0, 100)
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
		// TODO: Change to keyDoc.Results after re-index
		for _, res := range keyDoc.resultsForCompatibility() {
			ts := tsutil.ConvertMillis(res.Timestamp)

			// If verifiedAt age is too old skip it
			vts := tsutil.ConvertMillis(res.VerifiedAt)
			if !vts.IsZero() && u.clock.Now().Sub(vts) > maxAge {
				continue
			}

			if ts.IsZero() || u.clock.Now().Sub(ts) > dt {
				out = append(out, keyDoc.KID)
				break
			}
		}
	}
	iter.Release()

	return out, nil
}

// CheckForExisting returns key ID of user different from this sigchain key.
func (u *Users) CheckForExisting(ctx context.Context, sc *keys.Sigchain) (keys.ID, error) {
	users, err := FindInSigchain(sc)
	if err != nil {
		return "", err
	}
	for _, usr := range users {
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
		kids = append(kids, keyDoc.KID)
	}
	iter.Release()

	return kids, nil
}

// updateForTestingCompatibility is for testing backwards compatibility only.
// TODO: Remove after full re-index.
func (u *Users) updateForTestingCompatibility(ctx context.Context, kid keys.ID) (*Result, error) {
	sc, err := u.scs.Sigchain(kid)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, nil
	}

	results, err := u.CheckSigchain(ctx, sc)
	if err != nil {
		return nil, err
	}
	if len(results) > 1 {
		return nil, errors.Errorf("too many results for update")
	}
	var result *Result
	if len(results) == 1 {
		result = results[0]
	}

	keyDoc := &keyDocument{
		KID:    kid,
		Result: result,
	}
	if err := u.index(ctx, keyDoc); err != nil {
		return nil, err
	}

	return result, nil
}
