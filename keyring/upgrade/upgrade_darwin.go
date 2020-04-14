package upgrade

import (
	"github.com/keybase/go-keychain"
	"github.com/keys-pub/keys/keyring"
)

func keyringV1(st keyring.Store, serviceFrom string, keyFrom *[32]byte, serviceTo string, keyTo *[32]byte) {
	listQuery := keychain.NewItem()
	listQuery.SetSecClass(keychain.SecClassGenericPassword)
	listQuery.SetService(serviceFrom)

	listQuery.SetMatchLimit(keychain.MatchLimitAll)
	listQuery.SetReturnAttributes(true)
	results, err := keychain.QueryItem(listQuery)
	if err != nil {
		logger.Errorf("Failed to query for upgrade: %s", err)
		return
	} else if len(results) == 0 {
		return
	}

	logger.Infof("Found %d (for upgrade)", len(results))
	for _, r := range results {
		logger.Infof("Upgrade: %s", r.Account)
		if err := upgrade(st, serviceFrom, keyFrom, r.Account, serviceTo, keyTo); err != nil {
			logger.Errorf("Failed to upgrade %s: %s", r.Account, err)
			continue
		}
	}
}
