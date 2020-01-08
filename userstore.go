package keys

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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

type userResults struct {
	KID     ID            `json:"kid"`
	Results []*UserResult `json:"users,omitempty"`
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
func (u *UserStore) Update(ctx context.Context, kid ID) ([]*UserResult, error) {
	logger.Infof("Updating user index for %s", kid)
	sc, err := u.scs.Sigchain(kid)
	if err != nil {
		return []*UserResult{}, err
	}
	if sc == nil {
		return []*UserResult{}, nil
	}

	logger.Infof("Checking users %s", kid)
	results, err := u.checkSigchain(ctx, sc)
	if err != nil {
		return []*UserResult{}, err
	}

	res := &userResults{
		KID:     kid,
		Results: results,
	}

	logger.Infof("Indexing %s: %s", res.KID, strings.Join(userResultsStrings(res.Results), ","))
	if err := u.index(ctx, res); err != nil {
		return []*UserResult{}, err
	}

	return results, nil
}

func userResultsStrings(res []*UserResult) []string {
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.String())
	}
	return out
}

func (u *UserStore) checkSigchain(ctx context.Context, sc *Sigchain) ([]*UserResult, error) {
	users := sc.Users()

	results := make([]*UserResult, 0, len(users))
	for _, user := range users {
		result, err := u.result(ctx, sc.ID(), user.Service, user.Name)
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
		results = append(results, result)
	}

	return results, nil
}

// Check a user. Doesn't index result.
func (u *UserStore) Check(ctx context.Context, user *User, spk *SignPublicKey) (*UserResult, error) {
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

	msg := findSaltpackMessageInHTML(string(body), "")
	if msg == "" {
		logger.Warningf("User statement content not found")
		result.Err = "user signed message content not found"
		result.Status = UserStatusContentNotFound
		return nil
	}

	_, err = VerifyUser(msg, spk, result.User)
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

// Get users for KID.
func (u *UserStore) Get(ctx context.Context, kid ID) ([]*UserResult, error) {
	res, err := u.get(ctx, kid)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return []*UserResult{}, nil
	}
	return res.Results, nil
}

func (u *UserStore) get(ctx context.Context, kid ID) (*userResults, error) {
	if kid == "" {
		return nil, errors.Errorf("empty kid")
	}
	path := Path(indexKID, kid.String())
	doc, err := u.dst.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	var res userResults
	if err := json.Unmarshal(doc.Data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (u *UserStore) result(ctx context.Context, kid ID, service string, name string) (*UserResult, error) {
	results, err := u.get(ctx, kid)
	if err != nil {
		return nil, err
	}
	if results == nil {
		return nil, nil
	}
	for _, result := range results.Results {
		if result.User.Service == service && result.User.Name == name {
			return result, nil
		}
	}
	return nil, nil
}

func (u *UserStore) removeKID(ctx context.Context, kid ID) error {
	if err := u.removeExistingUsers(ctx, kid); err != nil {
		return err
	}

	idPath := Path(indexKID, kid.String())
	if _, err := u.dst.Delete(ctx, idPath); err != nil {
		return err
	}
	return nil
}

func (u *UserStore) removeExistingUsers(ctx context.Context, kid ID) error {
	entry, err := u.get(ctx, kid)
	if err != nil {
		return err
	}
	for _, result := range entry.Results {
		if err := u.removeUser(ctx, result.User); err != nil {
			return err
		}
	}
	return nil
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

func containsUser(results []*UserResult, result *UserResult) bool {
	for _, c := range results {
		if c.User.Service == result.User.Service && c.User.Name == result.User.Name {
			return true
		}
	}
	return false
}

type userDiff struct {
	add    []*UserResult
	remove []*UserResult
}

func (u *UserStore) diffUsers(ctx context.Context, kid ID, results []*UserResult) (*userDiff, error) {
	add := []*UserResult{}
	remove := []*UserResult{}

	result, err := u.get(ctx, kid)
	if err != nil {
		return nil, err
	}
	existing := []*UserResult{}
	if result != nil {
		existing = result.Results
	}

	for _, a := range results {
		if !containsUser(existing, a) {
			add = append(add, a)
		}
	}
	for _, r := range existing {
		if !containsUser(results, r) {
			remove = append(remove, r)
		}
	}
	return &userDiff{
		add:    add,
		remove: remove,
	}, nil
}

const indexKID = "kid"
const indexUser = "user"

func (u *UserStore) index(ctx context.Context, results *userResults) error {
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}

	diff, err := u.diffUsers(ctx, results.KID, results.Results)
	if err != nil {
		return err
	}
	for _, r := range diff.remove {
		if err := u.removeUser(ctx, r.User); err != nil {
			return err
		}
	}

	logger.Debugf("Data to index: %s", string(data))

	kidPath := Path(indexKID, results.KID.String())
	logger.Infof("Indexing kid %s", kidPath)
	if err := u.dst.Set(ctx, kidPath, data); err != nil {
		return err
	}

	for _, result := range results.Results {
		if result.Status != UserStatusOK {
			// TODO: Should we not remove on connection errors (or only if a temporary error persists)?
			logger.Infof("Removing failed user %s", result.User)
			if err := u.removeUser(ctx, result.User); err != nil {
				return err
			}
		} else {
			name := indexName(result.User)
			namePath := Path(indexUser, name)
			logger.Infof("Indexing user %s %s", namePath, result.User.KID)
			if err := u.dst.Set(ctx, namePath, data); err != nil {
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
		var res userResults
		if err := json.Unmarshal(doc.Data, &res); err != nil {
			return nil, err
		}
		for _, result := range res.Results {
			ts := TimeFromMillis(result.Timestamp)
			if ts.IsZero() || u.Now().Sub(ts) > dt {
				kids = append(kids, result.User.KID)
				break
			}
		}
	}
	iter.Release()

	return kids, nil
}
