package docs_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/keys-pub/keys/docs"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

func TestClock(t *testing.T) {
	clock := tsutil.NewTestClock()
	t1 := clock.Now()
	tf1 := t1.Format(tsutil.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.001Z", tf1)
	t2 := clock.Now()
	tf2 := t2.Format(tsutil.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.002Z", tf2)
}

func TestMem(t *testing.T) {
	mem := docs.NewMem()
	mem.SetClock(tsutil.NewTestClock())
	testDocuments(t, mem)
}

func TestMemListOptions(t *testing.T) {
	mem := docs.NewMem()
	mem.SetClock(tsutil.NewTestClock())
	testDocumentsListOptions(t, mem)
}

func TestMemMetadata(t *testing.T) {
	mem := docs.NewMem()
	mem.SetClock(tsutil.NewTestClock())
	testMetadata(t, mem)
}

func testDocuments(t *testing.T, ds docs.Documents) {
	ctx := context.TODO()

	for i := 10; i <= 30; i = i + 10 {
		p := docs.Path("test1", fmt.Sprintf("key%d", i))
		err := ds.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
	}
	for i := 10; i <= 30; i = i + 10 {
		p := docs.Path("test0", fmt.Sprintf("key%d", i))
		err := ds.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
	}

	iter, err := ds.DocumentIterator(ctx, "test0")
	require.NoError(t, err)
	doc, err := iter.Next()
	require.NoError(t, err)
	require.Equal(t, "/test0/key10", doc.Path)
	require.Equal(t, "value10", string(doc.Data))
	iter.Release()

	ok, err := ds.Exists(ctx, "/test0/key10")
	require.NoError(t, err)
	require.True(t, ok)
	doc, err = ds.Get(ctx, "/test0/key10")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "value10", string(doc.Data))

	err = ds.Create(ctx, "/test0/key10", []byte{})
	require.EqualError(t, err, "path already exists /test0/key10")
	err = ds.Set(ctx, "/test0/key10", []byte("overwrite"))
	require.NoError(t, err)
	err = ds.Create(ctx, "/test0/key10", []byte("overwrite"))
	require.EqualError(t, err, "path already exists /test0/key10")
	doc, err = ds.Get(ctx, "/test0/key10")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "overwrite", string(doc.Data))

	out, err := ds.GetAll(ctx, []string{"/test0/key10", "/test0/key20"})
	require.NoError(t, err)
	require.Equal(t, 2, len(out))
	require.Equal(t, "/test0/key10", out[0].Path)
	require.Equal(t, "/test0/key20", out[1].Path)

	ok, err = ds.Delete(ctx, "/test1/key10")
	require.True(t, ok)
	require.NoError(t, err)
	ok, err = ds.Delete(ctx, "/test1/key10")
	require.False(t, ok)
	require.NoError(t, err)

	ok, err = ds.Exists(ctx, "/test1/key10")
	require.NoError(t, err)
	require.False(t, ok)

	expected := `/test0/key10 overwrite
/test0/key20 value20
/test0/key30 value30
`
	var b bytes.Buffer
	iter, err = ds.DocumentIterator(context.TODO(), "test0")
	require.NoError(t, err)
	err = docs.SpewOut(iter, &b)
	require.NoError(t, err)
	require.Equal(t, expected, b.String())
	iter.Release()

	iter, err = ds.DocumentIterator(context.TODO(), "test0")
	require.NoError(t, err)
	spew, err := docs.Spew(iter)
	require.NoError(t, err)
	require.Equal(t, b.String(), spew.String())
	require.Equal(t, expected, spew.String())
	iter.Release()

	iter, err = ds.DocumentIterator(context.TODO(), "test0", docs.Prefix("key1"), docs.NoData())
	require.NoError(t, err)
	doc, err = iter.Next()
	require.NoError(t, err)
	require.Equal(t, "/test0/key10", doc.Path)
	doc, err = iter.Next()
	require.NoError(t, err)
	require.Nil(t, doc)
	iter.Release()

	err = ds.Create(ctx, "", []byte{})
	require.EqualError(t, err, "invalid path")
	err = ds.Set(ctx, "", []byte{})
	require.EqualError(t, err, "invalid path")

	cols, err := ds.Collections(ctx, "")
	require.NoError(t, err)
	require.Equal(t, "/test0", cols[0].Path)
	require.Equal(t, "/test1", cols[1].Path)

	_, err = ds.Collections(ctx, "/test0")
	require.EqualError(t, err, "only root collections supported")
}

func TestDocumentsPath(t *testing.T) {
	ds := docs.NewMem()
	ds.SetClock(tsutil.NewTestClock())
	ctx := context.TODO()

	err := ds.Create(ctx, "test/1", []byte("value1"))
	require.NoError(t, err)

	doc, err := ds.Get(ctx, "/test/1")
	require.NoError(t, err)
	require.NotNil(t, doc)

	ok, err := ds.Exists(ctx, "/test/1")
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = ds.Exists(ctx, "test/1")
	require.NoError(t, err)
	require.True(t, ok)

	err = ds.Create(ctx, docs.Path("test", "key2", "col2", "key3"), []byte("value3"))
	require.NoError(t, err)

	doc, err = ds.Get(ctx, docs.Path("test", "key2", "col2", "key3"))
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, []byte("value3"), doc.Data)

	cols, err := ds.Collections(ctx, "")
	require.NoError(t, err)
	require.Equal(t, "/test", cols[0].Path)
}

func testDocumentsListOptions(t *testing.T, ds docs.Documents) {
	ctx := context.TODO()

	err := ds.Create(ctx, "/test/1", []byte("val1"))
	require.NoError(t, err)
	err = ds.Create(ctx, "/test/2", []byte("val2"))
	require.NoError(t, err)
	err = ds.Create(ctx, "/test/3", []byte("val3"))
	require.NoError(t, err)

	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, docs.Path("a", fmt.Sprintf("e%d", i)), []byte("🤓"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, docs.Path("b", fmt.Sprintf("ea%d", i)), []byte("😎"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, docs.Path("b", fmt.Sprintf("eb%d", i)), []byte("😎"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, docs.Path("b", fmt.Sprintf("ec%d", i)), []byte("😎"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, docs.Path("c", fmt.Sprintf("e%d", i)), []byte("😎"))
		require.NoError(t, err)
	}

	iter, err := ds.DocumentIterator(ctx, "test")
	require.NoError(t, err)
	paths := []string{}
	for {
		doc, err := iter.Next()
		require.NoError(t, err)
		if doc == nil {
			break
		}
		paths = append(paths, doc.Path)
	}
	require.Equal(t, []string{"/test/1", "/test/2", "/test/3"}, paths)
	iter.Release()

	iter, err = ds.DocumentIterator(context.TODO(), "test")
	require.NoError(t, err)
	b, err := docs.Spew(iter)
	require.NoError(t, err)
	expected := `/test/1 val1
/test/2 val2
/test/3 val3
`
	require.Equal(t, expected, b.String())
	iter.Release()

	iter, err = ds.DocumentIterator(ctx, "b", docs.Prefix("eb"))
	require.NoError(t, err)
	paths = []string{}
	for {
		doc, err := iter.Next()
		require.NoError(t, err)
		if doc == nil {
			break
		}
		paths = append(paths, doc.Path)
	}
	iter.Release()
	require.Equal(t, []string{"/b/eb1", "/b/eb2"}, paths)
}

func testMetadata(t *testing.T, ds docs.Documents) {
	ctx := context.TODO()

	err := ds.Create(ctx, "/test/key1", []byte("value1"))
	require.NoError(t, err)

	doc, err := ds.Get(ctx, "/test/key1")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, int64(1234567890001), tsutil.Millis(doc.CreatedAt))

	err = ds.Set(ctx, "/test/key1", []byte("value1b"))
	require.NoError(t, err)

	doc, err = ds.Get(ctx, "/test/key1")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, int64(1234567890001), tsutil.Millis(doc.CreatedAt))
	require.Equal(t, int64(1234567890002), tsutil.Millis(doc.UpdatedAt))
}

func TestDeleteAll(t *testing.T) {
	mem := docs.NewMem()

	err := mem.Set(context.TODO(), "/test/key1", []byte("val1"))
	require.NoError(t, err)
	err = mem.Set(context.TODO(), "/test/key2", []byte("val2"))
	require.NoError(t, err)

	err = mem.DeleteAll(context.TODO(), []string{"/test/key1", "/test/key2", "/test/key3"})
	require.NoError(t, err)

	doc, err := mem.Get(context.TODO(), "/test/key1")
	require.NoError(t, err)
	require.Nil(t, doc)
	doc, err = mem.Get(context.TODO(), "/test/key2")
	require.NoError(t, err)
	require.Nil(t, doc)
}
