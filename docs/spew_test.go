package docs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSpew(t *testing.T) {
	docs := []*Document{
		NewDocument("/test/1").WithData([]byte("value1")),
		NewDocument("/test/2").WithData(bytes.Repeat([]byte{0xFF}, 16)),
		NewDocument("/test/3").WithData(bytes.Repeat([]byte{0xDD}, 32)),
		NewDocument("/test/4").WithData([]byte("value4")),
	}
	iter := NewIterator(docs...)

	spew, err := Spew(iter)
	require.NoError(t, err)
	expected := `/test/1 value1
/test/2
([]uint8) (len=16 cap=16) {
 00000000  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
}
/test/3
([]uint8) (len=32 cap=32) {
 00000000  dd dd dd dd dd dd dd dd  dd dd dd dd dd dd dd dd  |................|
 00000010  dd dd dd dd dd dd dd dd  dd dd dd dd dd dd dd dd  |................|
}
/test/4 value4
`
	t.Logf("\n%s", spew.String())
	require.Equal(t, expected, spew.String())
}
