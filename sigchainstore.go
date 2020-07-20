package keys

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/tsutil"
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

	// SigchainExists if true, has sigchain.
	SigchainExists(kid ID) (bool, error)

	// SetClock sets custom Clock.
	SetClock(clock tsutil.Clock)
}

type sigchainStore struct {
	ds    docs.Documents
	clock tsutil.Clock
}

// NewSigchainStore creates a SigchainStore from Documents.
func NewSigchainStore(ds docs.Documents) SigchainStore {
	return newSigchainStore(ds)
}

func newSigchainStore(ds docs.Documents) *sigchainStore {
	return &sigchainStore{
		ds:    ds,
		clock: tsutil.NewClock(),
	}
}

// SetTimeNow to use a custom time.Now.
func (s sigchainStore) SetClock(clock tsutil.Clock) {
	s.clock = clock
}

func (s sigchainStore) KIDs() ([]ID, error) {
	iter, err := s.ds.DocumentIterator(context.TODO(), "sigchain", docs.NoData())
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
		pc := docs.PathLast(doc.Path)
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
		b, err := st.Bytes()
		if err != nil {
			return err
		}
		if err := s.ds.Set(context.TODO(), docs.Path("sigchain", st.Key()), b); err != nil {
			return err
		}
	}
	return nil
}

func statementFromDocument(doc *docs.Document) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(doc.Data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s sigchainStore) Sigchain(kid ID) (*Sigchain, error) {
	logger.Debugf("Loading sigchain %s", kid)
	iter, err := s.ds.DocumentIterator(context.TODO(), "sigchain", docs.Prefix(kid.String()))
	if err != nil {
		return nil, err
	}

	sc := NewSigchain(kid)
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
	iter, err := s.ds.DocumentIterator(context.TODO(), "sigchain", docs.Prefix(kid.String()), docs.NoData())
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
		if _, err := s.ds.Delete(context.TODO(), path); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (s sigchainStore) SigchainExists(kid ID) (bool, error) {
	return s.ds.Exists(context.TODO(), docs.Path("sigchain", StatementKey(kid, 1)))
}
