package keyring

import (
	"sort"
	"strings"

	"github.com/danieljoos/wincred"
	"github.com/pkg/errors"
)

func newSystem(service string) Keyring {
	return sys{
		service: service,
	}
}

// CheckSystem returns error if wincred is not available.
func CheckSystem() error {
	return nil
}

type sys struct {
	service string
}

func (k sys) Name() string {
	return "wincred"
}

func (k sys) Get(id string) ([]byte, error) {
	targetName := k.service + "/" + id
	cred, err := wincred.GetGenericCredential(targetName)
	if err != nil {
		if errors.Cause(err) == wincred.ErrElementNotFound {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "wincred GetGenericCredential failed")
	}
	if cred == nil {
		return nil, nil
	}
	return cred.CredentialBlob, nil
}

func (k sys) Set(id string, data []byte) error {
	targetName := k.service + "/" + id
	cred := wincred.NewGenericCredential(targetName)
	cred.CredentialBlob = data
	if err := cred.Write(); err != nil {
		return errors.Wrapf(err, "wincred Write failed")
	}
	return nil
}

func (k sys) Delete(id string) (bool, error) {
	targetName := k.service + "/" + id
	cred, err := wincred.GetGenericCredential(targetName)
	if err != nil {
		if errors.Cause(err) == wincred.ErrElementNotFound {
			return false, nil
		}
		return false, errors.Wrapf(err, "wincred GetGenericCredential failed")
	}
	if cred == nil {
		return false, nil
	}
	if err := cred.Delete(); err != nil {
		return false, errors.Wrapf(err, "wincred Delete failed")
	}
	return true, nil
}

func (k sys) Exists(id string) (bool, error) {
	targetName := k.service + "/" + id
	cred, err := wincred.GetGenericCredential(targetName)
	if err != nil {
		if errors.Cause(err) == wincred.ErrElementNotFound {
			return false, nil
		}
		return false, errors.Wrapf(err, "wincred GetGenericCredential failed")
	}
	if cred == nil {
		return false, nil
	}
	return true, nil
}

func (k sys) Items(prefix string) ([]*Item, error) {
	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}

	out := make([]*Item, 0, len(creds))
	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, k.service+"/") {
			id := cred.TargetName[len(k.service+"/"):]
			if prefix != "" && !strings.HasPrefix(id, prefix) {
				continue
			}
			item := &Item{ID: id}
			b, err := k.Get(id)
			if err != nil {
				return nil, err
			}
			item.Data = b
			out = append(out, item)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (k sys) Reset() error {
	return reset(k)
}
