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

// Search for users.
func (u *Store) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	logger.Infof("Search users, query=%q, limit=%d", req.Query, req.Limit)
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}

	// Check if query is for key identifier
	kid, err := keys.ParseID(req.Query)
	if err == nil {
		res, err := u.findKID(ctx, kid)
		if err != nil {
			return nil, err
		}
		if res != nil {
			return []*SearchResult{res}, nil
		}
	}

	res, err := u.searchUsers(ctx, req.Query, limit)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (u *Store) findKID(ctx context.Context, kid keys.ID) (*SearchResult, error) {
	res, err := u.Get(ctx, kid)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return &SearchResult{
			KID:    kid,
			Result: res,
			Field:  "kid",
		}, nil
	}

	rkid, err := u.lookupRelated(ctx, kid)
	if err != nil {
		return nil, err
	}

	res, err = u.Get(ctx, rkid)
	if err != nil {
		return nil, err
	}
	if res != nil {
		return &SearchResult{
			KID:    kid,
			Result: res,
			Field:  "kid",
		}, nil
	}
	return nil, nil
}
