// +build !windows,!darwin

package upgrade

import "github.com/keys-pub/keys/keyring"

func keyringV1(st keyring.Store, serviceFrom string, keyFrom *[32]byte, serviceTo string, keyTo *[32]byte) {
	// Not supported
}
