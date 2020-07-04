package docs

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSpew(t *testing.T) {
	docs := []*Document{
		NewDocument("/test/1", []byte("value1")),
		NewDocument("/test/2", []byte{0xFF, 0x02, 0x03}),
		NewDocument("/test/3", bytes.Repeat([]byte{0x03}, 32)),
		NewDocument("/test/4", []byte("value4")),
	}
	iter := NewIterator(docs...)

	spew, err := Spew(iter)
	require.NoError(t, err)
	expected := `/test/1
([]uint8) (len=6 cap=6) {
 00000000  76 61 6c 75 65 31                                 |value1|
}

/test/2
([]uint8) (len=3 cap=3) {
 00000000  ff 02 03                                          |...|
}

/test/3
([]uint8) (len=32 cap=32) {
 00000000  03 03 03 03 03 03 03 03  03 03 03 03 03 03 03 03  |................|
 00000010  03 03 03 03 03 03 03 03  03 03 03 03 03 03 03 03  |................|
}

/test/4
([]uint8) (len=6 cap=6) {
 00000000  76 61 6c 75 65 34                                 |value4|
}

`
	t.Logf("\n%s", spew.String())
	require.Equal(t, expected, spew.String())
}
