package saltpack

import (
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

func convertErr(err error) error {
	if kerr, ok := err.(ksaltpack.ErrNoSenderKey); ok {
		kid, err := keys.NewID(keys.SignKeyType, kerr.Sender)
		if err != nil {
			return errors.Errorf("failed to parse sender key")
		}
		return keys.NewErrNotFound(kid.String())
	}
	// if err == ksaltpack.ErrNoDecryptionKey {
	// 	return keys.NewErrNotFound("", keys.PublicKeyType)
	// }
	return err
}
