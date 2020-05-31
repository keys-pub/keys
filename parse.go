package keys

import "github.com/pkg/errors"

// ParseKey tries to determine what key type and parses the key bytes.
func ParseKey(b []byte, password string) (Key, error) {
	b, typ := DetectDataType(b)
	logger.Debugf("Data type: %s", typ)
	switch typ {
	case IDType:
		logger.Debugf("Parsing ID: %s", string(b))
		id, err := ParseID(string(b))
		if err != nil {
			return nil, err
		}
		return id, nil
	case SaltpackArmoredType:
		return DecodeKeyFromSaltpack(string(b), password, false)
	case SSHPublicType:
		return ParseSSHPublicKey(string(b))
	case SSHType:
		return ParseSSHKey(b, []byte(password), true)
	default:
		return nil, errors.Errorf("unknown key format")
	}
}
