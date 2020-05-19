package keyring

// Copy data from a keyring to another keyring.
// It copies raw data, it doesn't need to be unlocked.
// Doesn't overwrite existing data.
func Copy(from *Keyring, to *Keyring) ([]string, error) {
	ids, err := from.Store().IDs(from.service, &IDsOpts{ShowReserved: true, ShowHidden: true})
	if err != nil {
		return nil, err
	}

	added := make([]string, 0, len(ids))
	for _, id := range ids {
		data, err := to.Store().Get(to.service, id)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			fromData, err := from.Store().Get(from.service, id)
			if err != nil {
				return nil, err
			}
			if err := to.Store().Set(to.service, id, fromData); err != nil {
				return nil, err
			}
			added = append(added, id)
		}
	}

	return added, nil
}
