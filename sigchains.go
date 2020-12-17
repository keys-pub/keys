package keys

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

// Sigchains stores sigchains.
type Sigchains struct {
	ds    dstore.Documents
	clock tsutil.Clock
}

// NewSigchains creates a Sigchains from Documents.
func NewSigchains(ds dstore.Documents) *Sigchains {
	return &Sigchains{
		ds:    ds,
		clock: tsutil.NewClock(),
	}
}

// SetClock to use a custom time.Now.
func (s *Sigchains) SetClock(clock tsutil.Clock) {
	s.clock = clock
}

// KIDs returns all key ids.
func (s *Sigchains) KIDs() ([]ID, error) {
	iter, err := s.ds.DocumentIterator(context.TODO(), "sigchain", dstore.NoData())
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
		pc := dstore.PathLast(doc.Path)
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

// Save sigchain.
func (s *Sigchains) Save(sc *Sigchain) error {
	if len(sc.Statements()) == 0 {
		return errors.Errorf("failed to save sigchain: no statements")
	}
	for _, st := range sc.Statements() {
		b, err := st.Bytes()
		if err != nil {
			return err
		}
		if st.Seq <= 0 {
			return errors.Errorf("statement sequence missing")
		}
		if err := s.ds.Set(context.TODO(), dstore.Path("sigchain", StatementID(st.KID, st.Seq)), dstore.Data(b)); err != nil {
			return err
		}
	}
	if err := s.Index(sc.KID()); err != nil {
		return err
	}
	return nil
}

func statementFromDocument(doc *dstore.Document) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(doc.Data(), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Sigchain returns sigchain for key.
func (s *Sigchains) Sigchain(kid ID) (*Sigchain, error) {
	// logger.Debugf("Loading sigchain %s", kid)
	iter, err := s.ds.DocumentIterator(context.TODO(), "sigchain", dstore.Prefix(kid.String()))
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

func (s *Sigchains) sigchainPaths(kid ID) ([]string, error) {
	iter, err := s.ds.DocumentIterator(context.TODO(), "sigchain", dstore.Prefix(kid.String()), dstore.NoData())
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

// Delete sigchain.
func (s *Sigchains) Delete(kid ID) (bool, error) {
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

	// TODO: Delete reverse key lookup?
	return true, nil
}

// Exists returns true if sigchain exists.
func (s *Sigchains) Exists(kid ID) (bool, error) {
	return s.ds.Exists(context.TODO(), dstore.Path("sigchain", StatementID(kid, 1)))
}

// indexRKL is collection for reverse key lookups.
const indexRKL = "rkl"

// Lookup key.
// Returns key associated with the specified key.
func (s *Sigchains) Lookup(kid ID) (ID, error) {
	path := dstore.Path(indexRKL, kid.String())
	doc, err := s.ds.Get(context.TODO(), path)
	if err != nil {
		return "", err
	}
	if doc == nil {
		return "", nil
	}
	rkid, err := ParseID(string(doc.Data()))
	if err != nil {
		return "", err
	}
	return rkid, nil
}

// Index key.
// Adds reverse key lookup for EdX25519 to X25519 public key.
func (s *Sigchains) Index(key Key) error {
	if key.Type() == EdX25519 {
		pk, err := NewEdX25519PublicKeyFromID(key.ID())
		if err != nil {
			return err
		}
		rk := pk.X25519PublicKey()
		rklPath := dstore.Path(indexRKL, rk.ID())
		// TODO: Store this as a string not as data.
		if err := s.ds.Set(context.TODO(), rklPath, dstore.Data([]byte(key.ID().String()))); err != nil {
			return err
		}
	}
	return nil
}
