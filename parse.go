package keys

import "github.com/pkg/errors"

// ParseKey tries to determine what key type and parses the key bytes.
func ParseKey(b []byte, password string) (Key, error) {
	typ := DetectDataType(b)
	switch typ {
	case IDType:
		id, err := ParseID(string(b))
		if err != nil {
			return nil, err
		}
		return id.Key()
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
