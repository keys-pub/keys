package dstore_test

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestDocument(t *testing.T) {
	mem := dstore.NewMem()
	clock := tsutil.NewTestClock()
	mem.SetClock(clock)
	ctx := context.TODO()

	paths := []string{}
	for i := 0; i < 4; i++ {
		p := dstore.Path("test", strconv.Itoa(i))
		err := mem.Create(ctx, p, dstore.Data([]byte(fmt.Sprintf("value%d", i))))
		require.NoError(t, err)
		paths = append(paths, p)
	}
	sort.Strings(paths)

	iter, err := mem.DocumentIterator(ctx, "test")
	require.NoError(t, err)
	out1, err := iter.Next()
	require.NoError(t, err)
	require.Equal(t, "/test/0", out1.Path)
	require.Equal(t, []byte("value0"), out1.Bytes("data"))
	require.Equal(t, int64(1234567890001), tsutil.Millis(out1.CreatedAt))

	out2, err := iter.Next()
	require.NoError(t, err)
	out3, err := iter.Next()
	require.NoError(t, err)
	out4, err := iter.Next()
	require.NoError(t, err)

	require.Equal(t, paths, []string{out1.Path, out2.Path, out3.Path, out4.Path})

	doc := dstore.NewDocument("test/6").WithData([]byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
	doc = dstore.NewDocument("//test//6").WithData([]byte("value6"))
	require.Equal(t, "/test/6", doc.Path)
}

func TestDocumentSetTo(t *testing.T) {
	mem := dstore.NewMem()
	clock := tsutil.NewTestClock()
	mem.SetClock(clock)
	ctx := context.TODO()

	type Test struct {
		Int    int    `json:"n,omitempty"`
		String string `json:"s,omitempty"`
		Bytes  []byte `json:"b,omitempty"`
	}
	val := &Test{
		Int:    1,
		String: "teststring",
		Bytes:  []byte("testbytes"),
	}

	path := dstore.Path("test", "key1")
	err := mem.Create(ctx, path, dstore.From(val))
	require.NoError(t, err)

	doc, err := mem.Get(ctx, path)
	require.NoError(t, err)

	var out Test
	err = doc.To(&out)
	require.NoError(t, err)
	require.Equal(t, val, &out)
}

func TestDocumentMerge(t *testing.T) {
	mem := dstore.NewMem()
	clock := tsutil.NewTestClock()
	mem.SetClock(clock)
	ctx := context.TODO()

	type Test struct {
		Int    int    `json:"n,omitempty"`
		String string `json:"s,omitempty"`
		Bytes  []byte `json:"b,omitempty"`
	}
	val := &Test{
		Int:    1,
		String: "teststring",
		Bytes:  []byte("testbytes"),
	}

	path := dstore.Path("test", "key1")
	err := mem.Set(ctx, path, dstore.From(val))
	require.NoError(t, err)

	val2 := &Test{String: "teststring-merge"}
	err = mem.Set(ctx, path, dstore.From(val2), dstore.MergeAll())
	require.NoError(t, err)

	doc, err := mem.Get(ctx, path)
	require.NoError(t, err)

	var out Test
	err = doc.To(&out)
	require.NoError(t, err)
	expected := &Test{
		Int:    1,
		String: "teststring-merge",
		Bytes:  []byte("testbytes"),
	}
	require.Equal(t, expected, &out)
}

func TestMarshal(t *testing.T) {
	type testType struct {
		Int    int    `json:"n"`
		String string `json:"s"`
		Bytes  []byte `json:"b"`
	}
	test := &testType{
		Int:    1,
		String: "teststring",
		Bytes:  []byte("testbytes"),
	}

	b, err := dstore.Marshal(test)
	require.NoError(t, err)

	expected := `([]uint8) (len=38 cap=64) {
 00000000  83 a1 6e d3 00 00 00 00  00 00 00 01 a1 73 aa 74  |..n..........s.t|
 00000010  65 73 74 73 74 72 69 6e  67 a1 62 c4 09 74 65 73  |eststring.b..tes|
 00000020  74 62 79 74 65 73                                 |tbytes|
}
`
	require.Equal(t, expected, spew.Sdump(b))

	var out testType
	err = dstore.Unmarshal(b, &out)
	require.NoError(t, err)

	require.Equal(t, test, &out)
}

func ExampleDocuments_Create() {
	ds := dstore.NewMem()

	type Test struct {
		Int    int    `json:"int,omitempty"`
		String string `json:"str,omitempty"`
		Bytes  []byte `json:"bytes,omitempty"`
	}
	val := &Test{
		Int:    1,
		String: "teststring",
		Bytes:  []byte("testbytes"),
	}

	path := dstore.Path("test", "doc1")
	if err := ds.Create(context.TODO(), path, dstore.From(val)); err != nil {
		log.Fatal(err)
	}
	doc, err := ds.Get(context.TODO(), path)
	if err != nil {
		log.Fatal(err)
	}
	var out Test
	if err = doc.To(&out); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%d\n", out.Int)
	fmt.Printf("%s\n", out.String)
	fmt.Printf("%s\n", string(out.Bytes))
	// Output:
	// 1
	// teststring
	// testbytes
}

func ExampleDocuments_Set() {
	ds := dstore.NewMem()

	type Test struct {
		Int    int    `json:"n,omitempty"`
		String string `json:"s,omitempty"`
		Bytes  []byte `json:"b,omitempty"`
	}
	val := &Test{
		Int:    1,
		String: "teststring",
		Bytes:  []byte("testbytes"),
	}

	path := dstore.Path("test", "doc1")
	if err := ds.Set(context.TODO(), path, dstore.From(val)); err != nil {
		log.Fatal(err)
	}

	// Merge
	val2 := Test{String: "teststring-merge"}
	if err := ds.Set(context.TODO(), path, dstore.From(val2), dstore.MergeAll()); err != nil {
		log.Fatal(err)
	}

	doc, err := ds.Get(context.TODO(), path)
	if err != nil {
		log.Fatal(err)
	}
	var out Test
	if err = doc.To(&out); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%d\n", out.Int)
	fmt.Printf("%s\n", out.String)
	fmt.Printf("%s\n", string(out.Bytes))
	// Output:
	// 1
	// teststring-merge
	// testbytes
}
