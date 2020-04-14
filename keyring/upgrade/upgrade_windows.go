package upgrade

import (
	"strings"

	"github.com/danieljoos/wincred"
	"github.com/keys-pub/keys/keyring"
)

func keyringV1(st keyring.Store, serviceFrom string, keyFrom *[32]byte, serviceTo string, keyTo *[32]byte) {
	creds, err := wincred.List()
	if err != nil {
		logger.Errorf("Failed to query for upgrade: %s", err)
		return
	}

	sys := keyring.System()

	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, serviceFrom+"/") {
			id := cred.TargetName[len(serviceFrom+"/"):]
			if err := upgrade(sys, serviceFrom, keyFrom, id, serviceTo, keyTo); err != nil {
				logger.Errorf("Failed to upgrade %s: %s", id, err)
				continue
			}
		}
	}
}
