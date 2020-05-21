package keyring

import (
	"sort"
	"strings"

	"github.com/danieljoos/wincred"
	"github.com/pkg/errors"
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

func (k sys) Set(service string, id string, data []byte) error {
	targetName := service + "/" + id
	cred := wincred.NewGenericCredential(targetName)
	cred.CredentialBlob = data
	if err := cred.Write(); err != nil {
		return errors.Wrapf(err, "wincred Write failed")
	}
	return nil
}

func (k sys) Delete(service string, id string) (bool, error) {
	targetName := service + "/" + id
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

func (k sys) Exists(service string, id string) (bool, error) {
	targetName := service + "/" + id
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

func (k sys) IDs(service string, opts *options.IDs) ([]string, error) {
	if opts == nil {
		opts = &options.IDs{}
	}
	prefix, showHidden, showReserved := opts.Prefix, opts.ShowHidden, opts.ShowReserved

	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(creds))
	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, service+"/") {
			id := cred.TargetName[len(service+"/"):]
			if !showReserved && strings.HasPrefix(id, ReservedPrefix) {
				continue
			}
			if !showHidden && strings.HasPrefix(id, HiddenPrefix) {
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
