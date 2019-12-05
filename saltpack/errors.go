package saltpack

import (
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

func convertErr(err error) error {
	if kerr, ok := err.(ksaltpack.ErrNoSenderKey); ok {
		kid, err := keys.NewID(kerr.Sender)
		if err != nil {
			return errors.Errorf("no sender key found (and no bytes available)")
		}
		return keys.NewErrNotFound(kid, keys.PublicKeyType)
	}
	// if err == ksaltpack.ErrNoDecryptionKey {
	// 	return keys.NewErrNotFound("", keys.PublicKeyType)
	// }
	return err
}
