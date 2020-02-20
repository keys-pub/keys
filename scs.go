package keys

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// SigchainStore provides access to sigchains, usually backed by a DocumentStore, such as a local db.
type SigchainStore interface {
	// KIDs returns all the sigchain KIDs.
	KIDs() ([]ID, error)

	// Sigchain for kid.
	Sigchain(kid ID) (*Sigchain, error)

	// SaveSigchain saves sigchain to the store.
	SaveSigchain(sc *Sigchain) error
	// DeleteSigchain deletes sigchain from the store.
	DeleteSigchain(kid ID) (bool, error)

	// SigchainExists if true, has sigchain
	SigchainExists(kid ID) (bool, error)

	// Now is current time.
	Now() time.Time
	// SetTimeNow sets clock.
	SetTimeNow(nowFn func() time.Time)
}

type sigchainStore struct {
	dst   DocumentStore
	nowFn func() time.Time
}

// NewSigchainStore creates a SigchainStore from a DocumentStore.
func NewSigchainStore(dst DocumentStore) SigchainStore {
	return newSigchainStore(dst)
}

func newSigchainStore(dst DocumentStore) *sigchainStore {
	return &sigchainStore{
		dst:   dst,
		nowFn: time.Now,
	}
}

// Now returns current time.
func (s sigchainStore) Now() time.Time {
	return s.nowFn()
}

// SetTimeNow to use a custom time.Now.
func (s sigchainStore) SetTimeNow(nowFn func() time.Time) {
	s.nowFn = nowFn
}

func (s sigchainStore) KIDs() ([]ID, error) {
	iter, err := s.dst.Documents(context.TODO(), "sigchain", &DocumentsOpts{PathOnly: true})
	if err != nil {
		return nil, err
	}
	ids := NewIDSet()
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		pc := LastPathComponent(doc.Path)
		str := strings.Split(pc, "-")[0]
		id, err := ParseID(str)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid path %q", doc.Path)
		}
		ids.Add(id)
	}
	iter.Release()
	return ids.IDs(), nil
}

func (s sigchainStore) SaveSigchain(sc *Sigchain) error {
	if len(sc.Statements()) == 0 {
		return errors.Errorf("failed to save sigchain: no statements")
	}
	for _, st := range sc.Statements() {
		if err := s.dst.Set(context.TODO(), Path("sigchain", st.Key()), st.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func statementFromDocument(doc *Document) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(doc.Data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s sigchainStore) Sigchain(kid ID) (*Sigchain, error) {
	logger.Debugf("Loading sigchain %s", kid)
	iter, err := s.dst.Documents(context.TODO(), "sigchain", &DocumentsOpts{Prefix: kid.String()})
	if err != nil {
		return nil, err
	}

	spk, err := SigchainPublicKeyFromID(kid)
	if err != nil {
		return nil, err
	}

	sc := NewSigchain(spk)
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		st, err := statementFromDocument(doc)
		if err != nil {
			return nil, err
		}
		if err := sc.Add(st); err != nil {
			return nil, err
		}
	}

	iter.Release()
	return sc, nil
}

func (s sigchainStore) sigchainPaths(kid ID) ([]string, error) {
	iter, err := s.dst.Documents(context.TODO(), "sigchain", &DocumentsOpts{Prefix: kid.String(), PathOnly: true})
	if err != nil {
		return nil, err
	}
	defer iter.Release()
	paths := make([]string, 0, 100)
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		paths = append(paths, doc.Path)
	}
	return paths, nil
}

func (s sigchainStore) DeleteSigchain(kid ID) (bool, error) {
	paths, err := s.sigchainPaths(kid)
	if err != nil {
		return false, err
	}

	if len(paths) == 0 {
		return false, nil
	}

	for _, path := range paths {
		if _, err := s.dst.Delete(context.TODO(), path); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (s sigchainStore) SigchainExists(kid ID) (bool, error) {
	return s.dst.Exists(context.TODO(), Path("sigchain", StatementKey(kid, 1)))
}
