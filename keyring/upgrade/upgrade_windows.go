package upgrade

import (
	"strings"

	"github.com/danieljoos/wincred"
	"github.com/keys-pub/keys/keyring"
)

// KeyringV1 upgrade.
func KeyringV1(serviceFrom string, serviceTo string, key *[32]byte) error {
	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}

	sys := keyring.System()

	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, service+"/") {
			id := cred.TargetName[len(service+"/"):]
			if strings.HasPrefix(id, hiddenPrefix) || strings.HasPrefix(id, reservedPrefix) {
				continue
			}
			if err := upgrade(sys, serviceFrom, serviceTo, id, key); err != nil {
				logger.Errorf("Failed to upgrade %s: %s", r.Account, err)
				continue
			}
		}
	}

	return nil
}
