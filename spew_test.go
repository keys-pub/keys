package keys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSpew(t *testing.T) {
	docs := []*Document{
		NewDocument("/test/1", []byte("value1")),
		NewDocument("/test/2", []byte{0xFF, 0x02, 0x03}),
	}
	iter := NewDocumentIterator(docs)

	spew, err := Spew(iter, nil)
	require.NoError(t, err)
	expected := `/test/1 value1
/test/2 ff0203
`
	require.Equal(t, expected, spew.String())
}
