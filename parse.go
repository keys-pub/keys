package keys

import (
	"github.com/pkg/errors"
)

// ParseKey tries to determine what key type and parses the key bytes.
func ParseKey(b []byte, password string) (Key, error) {
	b, typ := DetectEncoding(b)
	logger.Debugf("Encoding: %s", typ)
	switch typ {
	case IDEncoding:
		logger.Debugf("Parsing ID: %s", string(b))
		id, err := ParseID(string(b))
		if err != nil {
			return nil, err
		}
		return id, nil
	case SaltpackEncoding:
		return DecodeKey(string(b), SaltpackEncoding, password)
	case SSHEncoding:
		return DecodeKey(string(b), SSHEncoding, password)
	default:
		return nil, errors.Errorf("unknown key format")
	}
}
