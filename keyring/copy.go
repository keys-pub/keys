package keyring

// Copy data from a keyring to another keyring.
// It copies raw data, it doesn't need to be unlocked.
// Doesn't overwrite existing data.
func Copy(from Store, to Store) ([]string, error) {
	ids, err := from.IDs(Reserved(), Hidden())
	if err != nil {
		return nil, err
	}

	added := make([]string, 0, len(ids))
	for _, id := range ids {
		data, err := to.Get(id)
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			fromData, err := from.Get(id)
			if err != nil {
				return nil, err
			}
			if err := to.Set(id, fromData); err != nil {
				return nil, err
			}
			added = append(added, id)
		}
	}

	return added, nil
}
