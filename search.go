package keys

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

// Search index for sigchain information.
type Search struct {
	dst DocumentStore
	scs SigchainStore
	uc  *UserContext
}

// NewSearch creates a Search.
func NewSearch(dst DocumentStore, scs SigchainStore, uc *UserContext) *Search {
	return &Search{
		dst: dst,
		scs: scs,
		uc:  uc,
	}
}

// Get search result for KID.
func (s *Search) Get(ctx context.Context, kid ID) (*SearchResult, error) {
	if kid == "" {
		return nil, errors.Errorf("empty kid")
	}
	searchPath := Path(indexKID, kid.String())
	doc, err := s.dst.Get(ctx, searchPath)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	var res SearchResult
	if err := json.Unmarshal(doc.Data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Update search index for sigchain KID.
func (s *Search) Update(ctx context.Context, kid ID) error {
	logger.Infof("Updating search index for %s", kid)
	sc, err := s.scs.Sigchain(kid)
	if err != nil {
		return err
	}

	logger.Infof("Checking users %s", kid)
	users, err := s.uc.CheckSigchain(ctx, sc)
	if err != nil {
		return err
	}

	// bkids := sc.BKIDs()

	se := &SearchResult{
		KID: kid,
		// BKIDs: bkids,
		Users: users,
	}

	logger.Infof("Indexing %s, %+v", se.KID, se.Users)
	if err := s.index(ctx, se); err != nil {
		return err
	}

	return nil
}

func (s *Search) removeKID(ctx context.Context, kid ID) error {
	if err := s.removeExistingUsers(ctx, kid); err != nil {
		return err
	}

	idPath := Path(indexKID, kid.String())
	if _, err := s.dst.Delete(ctx, idPath); err != nil {
		return err
	}
	return nil
}

func (s *Search) removeExistingUsers(ctx context.Context, kid ID) error {
	entry, err := s.Get(ctx, kid)
	if err != nil {
		return err
	}
	for _, user := range entry.Users {
		if err := s.removeUser(ctx, user.User); err != nil {
			return err
		}
	}
	return nil
}

func (s *Search) removeUser(ctx context.Context, user *User) error {
	name := fmt.Sprintf("%s@%s", user.Name, user.Service)
	namePath := Path(indexUser, name)
	logger.Infof("Removing user %s: %s", user.KID, name)
	if _, err := s.dst.Delete(ctx, namePath); err != nil {
		return err
	}
	return nil
}

func containsUser(users []*UserCheck, user *UserCheck) bool {
	for _, u := range users {
		if u.User.Service == user.User.Service && u.User.Name == user.User.Name {
			return true
		}
	}
	return false
}

type userDiff struct {
	add    []*UserCheck
	remove []*UserCheck
}

func (s *Search) diffUsers(ctx context.Context, kid ID, users []*UserCheck) (*userDiff, error) {
	add := []*UserCheck{}
	remove := []*UserCheck{}

	result, err := s.Get(ctx, kid)
	if err != nil {
		return nil, err
	}
	existing := []*UserCheck{}
	if result != nil {
		existing = result.Users
	}

	for _, a := range users {
		if !containsUser(existing, a) {
			add = append(add, a)
		}
	}
	for _, r := range existing {
		if !containsUser(users, r) {
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

func (s *Search) index(ctx context.Context, res *SearchResult) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}

	diff, err := s.diffUsers(ctx, res.KID, res.Users)
	if err != nil {
		return err
	}
	for _, r := range diff.remove {
		if err := s.removeUser(ctx, r.User); err != nil {
			return err
		}
	}

	kidPath := Path(indexKID, res.KID.String())
	logger.Infof("Indexing kid %s", kidPath)
	if err := s.dst.Set(ctx, kidPath, data); err != nil {
		return err
	}

	for _, user := range res.Users {
		if user.Status != UserStatusOK {
			// TODO: Should we not remove on connection errors (or only if a temporary error persists)?
			logger.Infof("Removing failed user %s", user.User)
			if err := s.removeUser(ctx, user.User); err != nil {
				return err
			}
		} else {
			name := fmt.Sprintf("%s@%s", user.User.Name, user.User.Service)
			namePath := Path(indexUser, name)
			logger.Infof("Indexing user %s %s", namePath, user.User.KID)
			if err := s.dst.Set(ctx, namePath, data); err != nil {
				return err
			}
		}
	}

	return nil
}

// SearchField is fields to restrict search to.
type SearchField string

const (
	// UserField user field.
	UserField SearchField = "user"
	// KIDField KID field.
	KIDField SearchField = "kid"
)

// Contained returns true if this field is in fields.
func (f SearchField) Contained(fields []SearchField) bool {
	for _, field := range fields {
		if field == f {
			return true
		}
	}
	return false
}

// SearchRequest ...
type SearchRequest struct {
	// Query to search for.
	Query string
	// Limit number of results.
	Limit int
	// Fields if set, restrict search to those fields.
	Fields []SearchField
}

// SearchResult ...
type SearchResult struct {
	KID   ID           `json:"kid"`
	Users []*UserCheck `json:"users,omitempty"`
}

func (s *Search) search(ctx context.Context, parent string, query string, limit int) ([]*SearchResult, error) {
	logger.Infof("Searching %s", parent)
	iter, err := s.dst.Documents(ctx, parent, &DocumentsOpts{Prefix: query, Limit: limit})
	if err != nil {
		return nil, err
	}
	results := make([]*SearchResult, 0, limit)
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		var res SearchResult
		if err := json.Unmarshal(doc.Data, &res); err != nil {
			return nil, err
		}
		results = append(results, &res)
	}
	iter.Release()
	return results, nil
}

// Search for users.
func (s *Search) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	logger.Infof("Search users, query=%q, limit=%d", req.Query, req.Limit)
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}

	fields := req.Fields
	if len(fields) == 0 {
		fields = []SearchField{UserField, KIDField}
	}

	kids := NewIDSet()
	results := []*SearchResult{}

	for _, field := range fields {
		switch field {
		case UserField:
			res, err := s.search(ctx, indexUser, req.Query, limit-len(results))
			if err != nil {
				return nil, err
			}
			for _, r := range res {
				if !kids.Contains(r.KID) {
					results = append(results, r)
					kids.Add(r.KID)
				}
			}
		case KIDField:
			res, err := s.search(ctx, indexKID, req.Query, limit-len(results))
			if err != nil {
				return nil, err
			}
			for _, r := range res {
				if !kids.Contains(r.KID) {
					results = append(results, r)
					kids.Add(r.KID)
				}
			}
		}
	}

	return results, nil
}

// Expired returns KIDs that haven't been checked in a duration.
func (s *Search) Expired(ctx context.Context, dt time.Duration) ([]ID, error) {
	iter, err := s.dst.Documents(context.TODO(), indexKID, nil)
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
		var res SearchResult
		if err := json.Unmarshal(doc.Data, &res); err != nil {
			return nil, err
		}
		for _, user := range res.Users {
			if user.Timestamp.IsZero() || s.uc.Now().Sub(user.Timestamp) > dt {
				kids = append(kids, user.User.KID)
				break
			}
		}
	}
	iter.Release()

	return kids, nil
}
