package keys

import (
	"context"
	"encoding/json"
)

// UserSearchRequest ...
type UserSearchRequest struct {
	// Query to search for.
	Query string
	// Limit number of results.
	Limit int
}

// UserSearchResult ...
type UserSearchResult struct {
	KID ID `json:"kid"`
	// UserResult.
	UserResult *UserResult `json:"users"`
}

func (u *UserStore) search(ctx context.Context, query string, limit int) ([]*UserSearchResult, error) {
	logger.Infof("Searching users %q", query)
	iter, err := u.dst.Documents(ctx, indexUser, &DocumentsOpts{Prefix: query})
	if err != nil {
		return nil, err
	}

	results := make([]*UserSearchResult, 0, limit)
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		if len(results) >= limit {
			break
		}
		var keyDoc keyDocument
		if err := json.Unmarshal(doc.Data, &keyDoc); err != nil {
			return nil, err
		}

		results = append(results, &UserSearchResult{
			KID:        keyDoc.KID,
			UserResult: keyDoc.UserResult,
		})
	}
	iter.Release()
	logger.Infof("Found %d user results", len(results))
	return results, nil
}

// Search for users.
func (u *UserStore) Search(ctx context.Context, req *UserSearchRequest) ([]*UserSearchResult, error) {
	logger.Infof("Search users, query=%q, limit=%d", req.Query, req.Limit)
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}

	return u.search(ctx, req.Query, limit)
}
