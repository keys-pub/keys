package keyring

import "github.com/pkg/errors"

// Copy data from a keyring.Store to another keyring.Store.
// It copies raw data, it doesn't need to be unlocked.
// Doesn't overwrite existing data.
func Copy(from Store, to Store, opt ...CopyOption) ([]string, error) {
	opts := NewCopyOptions(opt...)

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
		if data != nil {
			if opts.SkipExisting {
				continue
			} else {
				return nil, errors.Errorf("failed to copy: entry already exists %s", id)
			}
		}
		fromData, err := from.Get(id)
		if err != nil {
			return nil, err
		}
		if !opts.DryRun {
			if err := to.Set(id, fromData); err != nil {
				return nil, err
			}
		}
		added = append(added, id)
	}

	return added, nil
}

// CopyOption ...
type CopyOption func(*CopyOptions)

// CopyOptions ...
type CopyOptions struct {
	SkipExisting bool
	DryRun       bool
}

// NewCopyOptions ...
func NewCopyOptions(opts ...CopyOption) CopyOptions {
	var options CopyOptions
	for _, o := range opts {
		o(&options)
	}
	return options
}

// SkipExisting to skip existing entries, otherwise error.
func SkipExisting() CopyOption {
	return func(o *CopyOptions) {
		o.SkipExisting = true
	}
}

// DryRun to pretend to copy.
func DryRun() CopyOption {
	return func(o *CopyOptions) {
		o.DryRun = true
	}
}
