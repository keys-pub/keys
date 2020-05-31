package backup

import "github.com/keys-pub/keys/keyring"

// Backup describes backup/restore for keyring.Store.
type Backup interface {
	Backup(service string, st keyring.Store) error
	Restore(service string, st keyring.Store) error
}
