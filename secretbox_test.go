package keys

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretBox(t *testing.T) {
	sk := GenerateSecretKey()
	nonce := Bytes24(bytes.Repeat([]byte{0x0F}, 24))
	b := []byte{0x01, 0x02, 0x03}
	encrypted := sealSecretBox(b, nonce, sk)
	out, err := openSecretBox(encrypted, sk)
	require.NoError(t, err)
	assert.Equal(t, b, out)
}
