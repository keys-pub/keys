package keyring_test

import (
	"runtime"
	"testing"

	"github.com/keys-pub/keys/ds"
	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func skipSystem(t *testing.T) bool {
	if runtime.GOOS == "linux" {
		if err := keyring.CheckSystem(); err != nil {
			t.Skip()
			return true
		}
	}
	return false
}

func TestStore(t *testing.T) {
	if skipSystem(t) {
		return
	}
	sys, err := keyring.NewSystem("KeysTest")
	require.NoError(t, err)
	defer func() { _ = sys.Reset() }()
	testStore(t, sys)
}

func testStore(t *testing.T, st keyring.Keyring) {
	paths, err := keyring.Paths(st, "")
	require.NoError(t, err)
	require.Equal(t, 0, len(paths))

	exists, err := st.Exists("key1")
	require.NoError(t, err)
	require.False(t, exists)

	data, err := st.Get("key1")
	require.NoError(t, err)
	require.Nil(t, data)

	err = st.Set("key1", []byte("val1"))
	require.NoError(t, err)

	out, err := st.Get("key1")
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, []byte("val1"), out)

	exists, err = st.Exists("key1")
	require.NoError(t, err)
	require.True(t, exists)

	err = st.Set("key1", []byte("val1.new"))
	require.NoError(t, err)

	out, err = st.Get("key1")
	require.NoError(t, err)
	require.Equal(t, []byte("val1.new"), out)

	docs, err := keyring.Documents(st, "")
	require.NoError(t, err)
	require.Equal(t, 1, len(docs))
	require.Equal(t, []byte("val1.new"), docs[0].Data)

	paths, err = keyring.Paths(st, "")
	require.NoError(t, err)
	require.Equal(t, 1, len(paths))
	require.Equal(t, paths[0], "key1")

	ok, err := st.Delete("key1")
	require.NoError(t, err)
	require.True(t, ok)

	out, err = st.Get("key1")
	require.NoError(t, err)
	require.Nil(t, out)

	exists, err = st.Exists("key1")
	require.NoError(t, err)
	require.False(t, exists)

	ok, err = st.Delete("key1")
	require.NoError(t, err)
	require.False(t, ok)

	docs, err = keyring.Documents(st, "")
	require.NoError(t, err)
	require.Equal(t, 0, len(docs))

	// Test paths
	err = st.Set("/collection/key1", []byte("val1"))
	require.NoError(t, err)

	out, err = st.Get("/collection/key1")
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, []byte("val1"), out)
}

func TestReset(t *testing.T) {
	if skipSystem(t) {
		return
	}
	sys, err := keyring.NewSystem("KeysTest")
	require.NoError(t, err)
	defer func() { _ = sys.Reset() }()
	testReset(t, sys)
}

func testReset(t *testing.T, st keyring.Keyring) {
	var err error
	err = st.Set("key1", []byte("password"))
	require.NoError(t, err)

	err = st.Reset()
	require.NoError(t, err)

	out, err := st.Get("key1")
	require.NoError(t, err)
	require.Nil(t, out)
}

func TestDocuments(t *testing.T) {
	if skipSystem(t) {
		return
	}
	sys, err := keyring.NewSystem("KeysTest")
	require.NoError(t, err)
	defer func() { _ = sys.Reset() }()
	testDocuments(t, sys)
}

func testDocuments(t *testing.T, st keyring.Keyring) {
	var err error

	// TODO: Implement index/limit options

	err = st.Set("akey1", []byte("aval1"))
	require.NoError(t, err)
	err = st.Set("akey2", []byte("aval2"))
	require.NoError(t, err)
	err = st.Set("bkey1", []byte("bval1"))
	require.NoError(t, err)

	docs := testDocumentsFromIterator(t, st, ds.NoData())
	require.Equal(t, 3, len(docs))
	require.Equal(t, "akey1", docs[0].Path)
	require.Nil(t, docs[0].Data)

	docs = testDocumentsFromIterator(t, st)
	require.Equal(t, 3, len(docs))
	require.Equal(t, "akey1", docs[0].Path)
	require.Equal(t, []byte("aval1"), docs[0].Data)

	docs = testDocumentsFromIterator(t, st, ds.Prefix("b"))
	require.Equal(t, 1, len(docs))
	require.Equal(t, "bkey1", docs[0].Path)
	require.Equal(t, []byte("bval1"), docs[0].Data)
}

func testDocumentsFromIterator(t *testing.T, st keyring.Keyring, opt ...ds.DocumentsOption) []*ds.Document {
	iter, err := st.Documents(opt...)
	require.NoError(t, err)
	defer iter.Release()
	docs := []*ds.Document{}
	for {
		doc, err := iter.Next()
		if err != nil {
			require.NoError(t, err)
		}
		if doc == nil {
			break
		}
		docs = append(docs, doc)
	}
	return docs

}
