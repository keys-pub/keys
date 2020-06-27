package user

import (
	"context"
	"encoding/json"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/ds"
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
}

func (u *Store) search(ctx context.Context, query string, limit int) ([]*SearchResult, error) {
	logger.Infof("Searching users %q", query)
	iter, err := u.dst.DocumentIterator(ctx, indexUser, ds.Prefix(query))
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
		var keyDoc keyDocument
		if err := json.Unmarshal(doc.Data, &keyDoc); err != nil {
			return nil, err
		}

		results = append(results, &SearchResult{
			KID:    keyDoc.KID,
			Result: keyDoc.Result,
		})
	}
	iter.Release()
	logger.Infof("Found %d user results", len(results))
	return results, nil
}

// Search for users.
func (u *Store) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	logger.Infof("Search users, query=%q, limit=%d", req.Query, req.Limit)
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}

	return u.search(ctx, req.Query, limit)
}
