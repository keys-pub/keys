package keyring_test

import (
	"bytes"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

type listener struct {
	unlocked   int
	provisions []*keyring.Provision
	locked     int
}

func (l *listener) Unlocked(p *keyring.Provision) {
	l.unlocked++
	l.provisions = append(l.provisions, p)
}

func (l *listener) Locked() {
	l.locked++
}

func TestListener(t *testing.T) {
	var err error

	ln := &listener{}
	kr := keyring.NewMem(false)
	kr.AddListener(ln)

	key := keys.Rand32()
	id := encoding.MustEncode(bytes.Repeat([]byte{0x01}, 32), encoding.Base62)
	provision := &keyring.Provision{ID: id}
	err = kr.Setup(key, provision)
	require.NoError(t, err)

	_, err = kr.Unlock(key)
	require.NoError(t, err)

	require.Equal(t, 1, ln.unlocked)
	require.Equal(t, 0, ln.locked)
	require.Equal(t, 1, len(ln.provisions))
	require.Equal(t, provision.ID, ln.provisions[0].ID)

	err = kr.Lock()
	require.NoError(t, err)
	require.Equal(t, 1, ln.unlocked)
	require.Equal(t, 1, ln.locked)

}
