package upgrade

import (
	"github.com/keybase/go-keychain"
	"github.com/keys-pub/keys/keyring"
)

// KeyringV1 upgrade.
func KeyringV1(serviceFrom string, serviceTo string, key *[32]byte) error {
	listQuery := keychain.NewItem()
	listQuery.SetSecClass(keychain.SecClassGenericPassword)
	listQuery.SetService(serviceFrom)

	listQuery.SetMatchLimit(keychain.MatchLimitAll)
	listQuery.SetReturnAttributes(true)
	results, err := keychain.QueryItem(listQuery)
	if err != nil {
		return err
	} else if len(results) == 0 {
		return nil
	}

	sys := keyring.System()

	for _, r := range results {
		if err := upgrade(sys, serviceFrom, serviceTo, r.Account, key); err != nil {
			logger.Errorf("Failed to upgrade %s: %s", r.Account, err)
			continue
		}
	}

	return nil
}
