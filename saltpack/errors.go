package saltpack

import (
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	ksaltpack "github.com/keybase/saltpack"
)

func convertErr(err error) error {
	if kerr, ok := err.(ksaltpack.ErrNoSenderKey); ok {
		id, err := bytesToID(kerr.Sender, keys.EdX25519Public)
		if err != nil {
			return errors.Wrapf(err, "failed to parse sender key")
		}
		return keys.NewErrNotFound(id.String())
	}
	// if err == ksaltpack.ErrNoDecryptionKey {
	// 	return keys.NewErrNotFound("", keys.PublicKeyType)
	// }
	return err
}
