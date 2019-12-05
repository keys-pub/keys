package keyring

import (
	"sort"
	"strings"

	"github.com/danieljoos/wincred"
	"github.com/pkg/errors"
)

func NewKeyring(service string) (Keyring, error) {
	if service == "" {
		return nil, errors.Errorf("no service specified")
	}
	kr, err := newKeyring(system, service)
	if err != nil {
		return nil, err
	}
	return &windows{kr}, nil
}

type windows struct {
	*keyring
}

// List items.
func (k *windows) List(opts *ListOpts) ([]*Item, error) {
	if opts == nil {
		opts = &ListOpts{}
	}
	if k.key == nil {
		return nil, ErrLocked
	}
	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}
	items := []*Item{}
	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, k.service+"/") {
			id := cred.TargetName[len(k.service+"/"):]
			if strings.HasPrefix(id, hiddenPrefix) || strings.HasPrefix(id, reservedPrefix) {
				continue
			}
			item, err := DecodeItem(cred.CredentialBlob, k.key)
			if err != nil {
				return nil, err
			}
			if opts.Type != "" && opts.Type != item.Type {
				continue
			}
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items, nil
}

var system = sys{}

type sys struct{}

func (k sys) get(service string, id string) ([]byte, error) {
	targetName := service + "/" + id
	cred, err := wincred.GetGenericCredential(targetName)
	if err != nil {
		if err.Error() == "Element not found." {
			return nil, nil
		}
		return nil, err
	}
	if cred == nil {
		return nil, nil
	}
	return cred.CredentialBlob, nil
}

func (k sys) set(service string, id string, data []byte, typ string) error {
	targetName := service + "/" + id
	cred := wincred.NewGenericCredential(targetName)
	cred.CredentialBlob = data
	return cred.Write()
}

func (k sys) remove(service string, id string) (bool, error) {
	targetName := service + "/" + id
	cred, err := wincred.GetGenericCredential(targetName)
	if err != nil {
		if err.Error() == "Element not found." {
			return false, nil
		}
		return false, err
	}
	if cred == nil {
		return false, nil
	}
	if err := cred.Delete(); err != nil {
		return false, err
	}
	return true, nil
}

func (k sys) exists(service string, id string) (bool, error) {
	targetName := service + "/" + id
	cred, err := wincred.GetGenericCredential(targetName)
	if err != nil {
		if err.Error() == "Element not found." {
			return false, nil
		}
		return false, err
	}
	if cred == nil {
		return false, nil
	}
	return true, nil
}

func (k sys) ids(service string, prefix string, showHidden bool, showReserved bool) ([]string, error) {
	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(creds))
	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, service+"/") {
			id := cred.TargetName[len(service+"/"):]
			if !showHidden && strings.HasPrefix(id, reservedPrefix) {
				continue
			}
			if !showHidden && strings.HasPrefix(id, hiddenPrefix) {
				continue
			}
			if prefix != "" && !strings.HasPrefix(id, prefix) {
				continue
			}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Utility to dump wincred list:
// func main() {
// 	creds, err := wincred.List()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	for _, cred := range creds {
// 		fmt.Println(cred.TargetName)
// 		spew.Dump(cred.CredentialBlob)
// 		fmt.Println("")
// 	}
// }
