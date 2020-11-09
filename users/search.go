package users

import (
	"context"
	"encoding/json"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/user"
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
	Result *user.Result
	// Field we matched on (if not the user).
	Field string
}

func (u *Users) searchUsers(ctx context.Context, query string, limit int) ([]*SearchResult, error) {
	logger.Infof("Searching users %q", query)
	iter, err := u.ds.DocumentIterator(ctx, indexSearch, dstore.Prefix(query))
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
		if err := json.Unmarshal(doc.Data(), &keyDoc); err != nil {
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
		if res != nil {
			return []*SearchResult{&SearchResult{
				KID:    kid,
				Result: res,
				Field:  "kid",
			}}, nil
		}
	}

	res, err := u.searchUsers(ctx, req.Query, limit)
	if err != nil {
		return nil, err
	}
	return res, nil
}
