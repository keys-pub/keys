package keys_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

type clock struct {
	t time.Time
}

func newClock() *clock {
	t := keys.TimeFromMillis(1234567890000)
	return &clock{
		t: t,
	}
}

func (c *clock) Now() time.Time {
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func TestMem(t *testing.T) {
	mem := keys.NewMem()
	mem.SetTimeNow(newClock().Now)
	require.Equal(t, "mem://", mem.URI())
	testDocumentStore(t, mem)
}

func TestMemPath(t *testing.T) {
	mem := keys.NewMem()
	mem.SetTimeNow(newClock().Now)
	testDocumentStorePath(t, mem)
}

func TestMemListOptions(t *testing.T) {
	mem := keys.NewMem()
	mem.SetTimeNow(newClock().Now)
	testDocumentStoreListOptions(t, mem)
}

func TestMemChanges(t *testing.T) {
	mem := keys.NewMem()
	mem.SetTimeNow(newClock().Now)
	testChanges(t, mem, mem)
}

func TestMemMetadata(t *testing.T) {
	mem := keys.NewMem()
	mem.SetTimeNow(newClock().Now)
	testMetadata(t, mem)
}

func testDocumentStore(t *testing.T, ds keys.DocumentStore) {
	ctx := context.TODO()

	for i := 10; i <= 30; i = i + 10 {
		p := keys.Path("test1", fmt.Sprintf("key%d", i))
		err := ds.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
	}
	for i := 10; i <= 30; i = i + 10 {
		p := keys.Path("test0", fmt.Sprintf("key%d", i))
		err := ds.Create(ctx, p, []byte(fmt.Sprintf("value%d", i)))
		require.NoError(t, err)
	}

	iter, err := ds.Documents(ctx, "test0", nil)
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

	docs, err := ds.GetAll(ctx, []string{"/test0/key10", "/test0/key20"})
	require.NoError(t, err)
	require.Equal(t, 2, len(docs))
	require.Equal(t, "/test0/key10", docs[0].Path)
	require.Equal(t, "/test0/key20", docs[1].Path)

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
	iter, err = ds.Documents(context.TODO(), "test0", nil)
	require.NoError(t, err)
	err = keys.SpewOut(iter, nil, &b)
	require.NoError(t, err)
	require.Equal(t, expected, b.String())
	iter.Release()

	iter, err = ds.Documents(context.TODO(), "test0", nil)
	require.NoError(t, err)
	spew, err := keys.Spew(iter, nil)
	require.NoError(t, err)
	require.Equal(t, b.String(), spew.String())
	require.Equal(t, expected, spew.String())
	iter.Release()

	iter, err = ds.Documents(context.TODO(), "test0", &keys.DocumentsOpts{Prefix: "key1", PathOnly: true})
	require.NoError(t, err)
	doc, err = iter.Next()
	require.NoError(t, err)
	require.Equal(t, "/test0/key10", doc.Path)
	doc, err = iter.Next()
	require.NoError(t, err)
	require.Nil(t, doc)
	iter.Release()

	err = ds.Create(ctx, "", []byte{})
	require.EqualError(t, err, "invalid path /")
	err = ds.Set(ctx, "", []byte{})
	require.EqualError(t, err, "invalid path /")

	citer, err := ds.Collections(ctx, "")
	require.NoError(t, err)
	col, err := citer.Next()
	require.NoError(t, err)
	require.Equal(t, "/test0", col.Path)
	col, err = citer.Next()
	require.NoError(t, err)
	require.Equal(t, "/test1", col.Path)
	col, err = citer.Next()
	require.NoError(t, err)
	require.Nil(t, col)
	citer.Release()

	_, err = ds.Collections(ctx, "/test0")
	require.EqualError(t, err, "only root collections supported")
}

func testDocumentStorePath(t *testing.T, ds keys.DocumentStore) {
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
}

func testDocumentStoreListOptions(t *testing.T, ds keys.DocumentStore) {
	ctx := context.TODO()

	err := ds.Create(ctx, "/test/1", []byte("val1"))
	require.NoError(t, err)
	err = ds.Create(ctx, "/test/2", []byte("val2"))
	require.NoError(t, err)
	err = ds.Create(ctx, "/test/3", []byte("val3"))
	require.NoError(t, err)

	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, keys.Path("a", fmt.Sprintf("e%d", i)), []byte("🤓"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, keys.Path("b", fmt.Sprintf("ea%d", i)), []byte("😎"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, keys.Path("b", fmt.Sprintf("eb%d", i)), []byte("😎"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, keys.Path("b", fmt.Sprintf("ec%d", i)), []byte("😎"))
		require.NoError(t, err)
	}
	for i := 1; i < 3; i++ {
		err := ds.Create(ctx, keys.Path("c", fmt.Sprintf("e%d", i)), []byte("😎"))
		require.NoError(t, err)
	}

	iter, err := ds.Documents(ctx, "test", nil)
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

	iter, err = ds.Documents(context.TODO(), "test", nil)
	require.NoError(t, err)
	b, err := keys.Spew(iter, nil)
	require.NoError(t, err)
	expected := `/test/1 val1
/test/2 val2
/test/3 val3
`
	require.Equal(t, expected, b.String())
	iter.Release()

	iter, err = ds.Documents(ctx, "b", &keys.DocumentsOpts{Prefix: "eb"})
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

func testMetadata(t *testing.T, ds keys.DocumentStore) {
	ctx := context.TODO()

	err := ds.Create(ctx, "/test/key1", []byte("value1"))
	require.NoError(t, err)

	doc, err := ds.Get(ctx, "/test/key1")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, keys.TimeMs(1234567890001), keys.TimeToMillis(doc.CreatedAt))

	err = ds.Set(ctx, "/test/key1", []byte("value1b"))
	require.NoError(t, err)

	doc, err = ds.Get(ctx, "/test/key1")
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, keys.TimeMs(1234567890001), keys.TimeToMillis(doc.CreatedAt))
	require.Equal(t, keys.TimeMs(1234567890002), keys.TimeToMillis(doc.UpdatedAt))
}
