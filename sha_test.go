package keys

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSHA256(t *testing.T) {
	b := bytes.Repeat([]byte{1}, 1024)
	out := SHA256(b)
	require.Equal(t, "5a648d8015900d89664e00e125df179636301a2d8fa191c1aa2bd9358ea53a69", hex.EncodeToString(out))
}
