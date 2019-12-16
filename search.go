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
	return unmarshalSearchResult(doc.Data)
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
	data := marshalSearchResult(res)

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

// SearchRequest ...
type SearchRequest struct {
	Query string
	Index int
	Limit int
	KIDs  bool
}

// SearchResult ...
type SearchResult struct {
	KID   ID           `json:"kid"`
	Users []*UserCheck `json:"users"`
}

func marshalSearchResult(res *SearchResult) []byte {
	b, _ := json.Marshal(res)
	return b
}

func unmarshalSearchResult(b []byte) (*SearchResult, error) {
	var val SearchResult
	if err := json.Unmarshal(b, &val); err != nil {
		return nil, err
	}
	return &val, nil
}

// Search for users.
func (s *Search) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	logger.Infof("Search users, query=%q, index=%d, limit=%d, kids=%t", req.Query, req.Index, req.Limit, req.KIDs)
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}

	logger.Debugf("Searching users...")
	iter, err := s.dst.Documents(ctx, indexUser, &DocumentsOpts{Prefix: req.Query, Index: req.Index, Limit: limit})
	if err != nil {
		return nil, err
	}
	kids := NewIDSet()
	results := []*SearchResult{}

	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		res, err := unmarshalSearchResult(doc.Data)
		if err != nil {
			return nil, err
		}
		if !kids.Contains(res.KID) {
			results = append(results, res)
			kids.Add(res.KID)
		}
	}
	iter.Release()

	if req.KIDs {
		logger.Debugf("Searching KIDs...")
		iter, err = s.dst.Documents(ctx, indexKID, &DocumentsOpts{Prefix: req.Query})
		if err != nil {
			return nil, err
		}
		for {
			if len(results) >= limit {
				break
			}
			doc, err := iter.Next()
			if err != nil {
				return nil, err
			}
			if doc == nil {
				break
			}
			res, err := unmarshalSearchResult(doc.Data)
			if err != nil {
				return nil, err
			}
			if !kids.Contains(res.KID) {
				results = append(results, res)
				kids.Add(res.KID)
			}
		}
		iter.Release()
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
		res, err := unmarshalSearchResult(doc.Data)
		if err != nil {
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
