package keys

import (
	"context"
	"encoding/json"
	"strings"
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
	// UserResults, with matched results at the beginning (of length MatchCount).
	UserResults []*UserResult `json:"users"`
	// MatchCount, is number of matched results.
	MatchCount int `json:"matchCount"`
}

func (u *UserStore) search(ctx context.Context, query string, limit int) ([]*UserSearchResult, error) {
	logger.Infof("Searching users %q", query)
	iter, err := u.dst.Documents(ctx, indexUser, &DocumentsOpts{Prefix: query})
	if err != nil {
		return nil, err
	}

	kids := NewIDSet()
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

		if kids.Contains(keyDoc.KID) {
			continue
		}
		kids.Add(keyDoc.KID)

		userResults := keyDoc.UserResults
		if userResults == nil {
			// Set empty array instead of nil
			userResults = []*UserResult{}
		}
		results = append(results, &UserSearchResult{
			KID:         keyDoc.KID,
			UserResults: keyDoc.UserResults,
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

	results, err := u.search(ctx, req.Query, limit)
	if err != nil {
		return nil, err
	}

	out := make([]*UserSearchResult, 0, len(results))
	// Re-order so matched are first
	for _, res := range results {
		matched := make([]*UserResult, 0, len(res.UserResults))
		unmatched := make([]*UserResult, 0, len(res.UserResults))
		count := 0
		for _, r := range res.UserResults {
			if strings.HasPrefix(r.User.String(), req.Query) {
				matched = append(matched, r)
				count++
			} else {
				unmatched = append(unmatched, r)
			}
		}
		out = append(out, &UserSearchResult{
			KID:         res.KID,
			UserResults: append(matched, unmatched...),
			MatchCount:  count,
		})
	}

	return out, nil
}
