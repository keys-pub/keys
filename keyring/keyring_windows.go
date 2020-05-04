package keyring

import (
	"sort"
	"strings"

	"github.com/danieljoos/wincred"
)

// System returns keyring store for windows.
func system() Store {
	return sys{}
}

func checkSystem() error {
	return nil
}

type sys struct{}

func (k sys) Name() string {
	return "wincred"
}

func (k sys) Get(service string, id string) ([]byte, error) {
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

func (k sys) Set(service string, id string, data []byte, typ string) error {
	targetName := service + "/" + id
	cred := wincred.NewGenericCredential(targetName)
	cred.CredentialBlob = data
	return cred.Write()
}

func (k sys) Delete(service string, id string) (bool, error) {
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

func (k sys) Exists(service string, id string) (bool, error) {
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

func (k sys) List(service string, key SecretKey, opts *ListOpts) ([]*Item, error) {
	if opts == nil {
		opts = &ListOpts{}
	}
	if key == nil {
		return nil, ErrLocked
	}
	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}
	items := []*Item{}
	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, service+"/") {
			id := cred.TargetName[len(service+"/"):]
			if strings.HasPrefix(id, hiddenPrefix) || strings.HasPrefix(id, reservedPrefix) {
				continue
			}
			item, err := DecodeItem(cred.CredentialBlob, key)
			if err != nil {
				return nil, err
			}
			if len(opts.Types) != 0 && !contains(opts.Types, item.Type) {
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

func (k sys) IDs(service string, prefix string, showHidden bool, showReserved bool) ([]string, error) {
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

func (k sys) Reset(service string) error {
	return resetDefault(k, service)
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
