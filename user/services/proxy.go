package services

import (
	"github.com/keys-pub/keys"
)

type userStatus struct {
	ID         string  `json:"id,omitempty"`
	Name       string  `json:"name,omitempty"`
	KID        keys.ID `json:"kid,omitempty"`
	Seq        int     `json:"seq,omitempty"`
	Service    string  `json:"service,omitempty"`
	URL        string  `json:"url,omitempty"`
	Status     string  `json:"status,omitempty"`
	Statement  string  `json:"statement,omitempty"`
	VerifiedAt int64   `json:"verifiedAt,omitempty"`
	Timestamp  int64   `json:"ts,omitempty"`
	MatchField string  `json:"mf,omitempty"`
	Err        string  `json:"err,omitempty"`
}

// func CheckContent(name string, b []byte) ([]byte, error) {
// 	var status userStatus
// 	if err := json.Unmarshal(b, &status); err != nil {
// 		return nil, err
// 	}
// 	if status.Status != "ok" {
// 		return nil, errors.Errorf("status not ok")
// 	}

// 	if name != status.Name {
// 		return nil, errors.Errorf("invalid user name")
// 	}

// 	if "twitter" != status.Service {
// 		return nil, errors.Errorf("invalid user service")
// 	}

// 	return []byte(status.Statement), nil
// }

// func Request(ctx context.Context, client http.Client, urs string) ([]byte, error) {
// 	req, err := http.NewRequest("GET", urs, nil)
// 	if err != nil {
// 		return nil, err
// 	}
// 	b, err := client.Request(ctx, req, nil)
// 	if err != nil {
// 		if errHTTP, ok := errors.Cause(err).(http.Error); ok && errHTTP.StatusCode == 404 {
// 			return nil, nil
// 		}
// 		return nil, err
// 	}
// 	return b, nil
// }
