package keyring_test

import (
	"testing"

	"github.com/keys-pub/keys/keyring"
	"github.com/stretchr/testify/require"
)

func testStore(t *testing.T, st keyring.Store) {
	ids, err := st.IDs()
	require.NoError(t, err)
	require.Equal(t, 0, len(ids))

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

	ids, err = st.IDs()
	require.NoError(t, err)
	require.Equal(t, 1, len(ids))
	require.Equal(t, ids[0], "key1")

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
}
