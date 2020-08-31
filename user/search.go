package user

import (
	"context"
	"encoding/json"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/docs"
)

// SearchRequest ...
type SearchRequest struct {
	// Query to search for.
	Query string
	// Limit number of results.
	Limit int
}

// SearchResult ...
type SearchResult struct {
	KID    keys.ID
	Result *Result
	// Field we matched on (if not the user).
	Field string
}

func (u *Users) searchUsers(ctx context.Context, query string, limit int) ([]*SearchResult, error) {
	logger.Infof("Searching users %q", query)
	iter, err := u.ds.DocumentIterator(ctx, indexSearch, docs.Prefix(query))
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
		if len(results) >= limit {
			break
		}
		var userDoc userDocument
		if err := json.Unmarshal(doc.Data, &userDoc); err != nil {
			return nil, err
		}

		results = append(results, &SearchResult{
			KID:    userDoc.KID,
			Result: userDoc.Result,
		})
	}
	iter.Release()
	logger.Infof("Found %d user results", len(results))
	return results, nil
}

// Search for users.
func (u *Users) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	logger.Infof("Search users, query=%q, limit=%d", req.Query, req.Limit)
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}

	// Check if query is for a key identifier.
	kid, err := keys.ParseID(req.Query)
	if err == nil {
		res, err := u.Find(ctx, kid)
		if err != nil {
			return nil, err
		}
		out := []*SearchResult{}
		for _, r := range res {
			out = append(out, &SearchResult{
				KID:    kid,
				Result: r,
				Field:  "kid",
			})
		}
		return out, nil
	}

	res, err := u.searchUsers(ctx, req.Query, limit)
	if err != nil {
		return nil, err
	}
	return res, nil
}
