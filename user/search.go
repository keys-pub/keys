package user

import (
	"context"
	"encoding/json"
	"strings"

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

func (u *Store) searchUsers(ctx context.Context, query string, limit int) ([]*SearchResult, error) {
	logger.Infof("Searching users %q", query)
	iter, err := u.ds.DocumentIterator(ctx, indexUser, docs.Prefix(query))
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

func (u *Store) searchKIDs(ctx context.Context, query string, limit int) ([]*SearchResult, error) {
	logger.Infof("Searching kid %q", query)
	iter, err := u.ds.DocumentIterator(ctx, indexKID, docs.Prefix(query))
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
			Field:  "kid",
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

	res, err := u.searchUsers(ctx, req.Query, limit)
	if err != nil {
		return nil, err
	}

	// Search kid's if prefix is kex1
	if strings.HasPrefix(req.Query, "kex1") {
		resKIDs, err := u.searchKIDs(ctx, req.Query, limit-len(res))
		if err != nil {
			return nil, err
		}
		res = append(res, resKIDs...)
	}

	return res, nil
}
