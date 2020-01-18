package keys

import (
	"context"
	"encoding/json"
)

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
	KID         ID            `json:"kid"`
	UserResults []*UserResult `json:"users,omitempty"`
}

func (u *UserStore) search(ctx context.Context, parent string, query string, limit int) ([]*SearchResult, error) {
	logger.Infof("Searching %s %q", parent, query)
	iter, err := u.dst.Documents(ctx, parent, &DocumentsOpts{Prefix: query, Limit: limit})
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
		var userDoc userDocument
		if err := json.Unmarshal(doc.Data, &userDoc); err != nil {
			return nil, err
		}
		results = append(results, &SearchResult{
			KID:         userDoc.KID,
			UserResults: userDoc.UserResults,
		})
	}
	iter.Release()
	logger.Infof("Found %d user results", len(results))
	return results, nil
}

func dedupe(res []*SearchResult, limit int) []*SearchResult {
	kids := NewIDSet()
	results := make([]*SearchResult, 0, len(res))
	for _, r := range res {
		if !kids.Contains(r.KID) {
			results = append(results, r)
			kids.Add(r.KID)
		}
		if len(results) == limit {
			break
		}
	}
	return results
}

// Search for users.
func (u *UserStore) Search(ctx context.Context, req *SearchRequest) ([]*SearchResult, error) {
	logger.Infof("Search users, query=%q, limit=%d", req.Query, req.Limit)
	limit := req.Limit
	if limit == 0 {
		limit = 100
	}

	fields := req.Fields
	if len(fields) == 0 {
		fields = []SearchField{UserField, KIDField}
	}

	results := []*SearchResult{}

	for _, field := range fields {
		switch field {
		case UserField:
			res, err := u.search(ctx, indexUser, req.Query, limit)
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		case KIDField:
			res, err := u.search(ctx, indexKID, req.Query, limit)
			if err != nil {
				return nil, err
			}
			results = append(results, res...)
		}
	}

	results = dedupe(results, limit)

	return results, nil
}
