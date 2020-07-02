package keys_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestDetect(t *testing.T) {
	_, typ := keys.DetectEncoding([]byte("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"))
	require.Equal(t, keys.IDEncoding, typ)

	_, typ = keys.DetectEncoding([]byte("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph07"))
	require.Equal(t, keys.IDEncoding, typ)

	_, typ = keys.DetectEncoding([]byte("kex132yw8ht5p8cetl2mvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"))
	require.Equal(t, keys.IDEncoding, typ)

	_, typ = keys.DetectEncoding([]byte("kex132yw8ht5p8cetl2mvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077   "))
	require.Equal(t, keys.IDEncoding, typ)

	_, typ = keys.DetectEncoding([]byte("BEGIN MESSAGE. ok END MESSAGE."))
	require.Equal(t, keys.SaltpackEncoding, typ)

	_, typ = keys.DetectEncoding([]byte("BEGIN MESSAGE. ok "))
	require.Equal(t, keys.SaltpackEncoding, typ)

	_, typ = keys.DetectEncoding([]byte("BEGIN MESSAGE"))
	require.Equal(t, keys.SaltpackEncoding, typ)

	_, typ = keys.DetectEncoding([]byte{})
	require.Equal(t, keys.UnknownEncoding, typ)

	_, typ = keys.DetectEncoding(nil)
	require.Equal(t, keys.UnknownEncoding, typ)
}
