package dstore_test

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"testing"

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

func TestDocumentTo(t *testing.T) {
	mem := dstore.NewMem()
	clock := tsutil.NewTestClock()
	mem.SetClock(clock)
	ctx := context.TODO()

	type testType struct {
		Int    int
		String string
		Bytes  []byte
	}
	test := &testType{
		Int:    1,
		String: "teststring",
		Bytes:  []byte("testbytes"),
	}

	path := dstore.Path("test", "key1")
	err := mem.Create(ctx, path, dstore.From(test))
	require.NoError(t, err)

	doc, err := mem.Get(ctx, path)
	require.NoError(t, err)

	var out testType
	err = doc.To(&out)
	require.NoError(t, err)
	require.Equal(t, test, &out)
}

func ExampleDocuments_Create() {
	ds := dstore.NewMem()

	type Example struct {
		Int    int
		String string
		Bytes  []byte
	}
	example := &Example{
		Int:    1,
		String: "teststring",
		Bytes:  []byte("testbytes"),
	}

	path := dstore.Path("examples", "example1")
	if err := ds.Create(context.TODO(), path, dstore.From(example)); err != nil {
		log.Fatal(err)
	}
	doc, err := ds.Get(context.TODO(), path)
	if err != nil {
		log.Fatal(err)
	}
	var out Example
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
