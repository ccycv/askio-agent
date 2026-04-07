package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStorePutGet(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFileStore(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx := context.Background()
	if err := st.Put(ctx, "b", "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	b, ok, err := st.Get(ctx, "b", "k")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(b) != "v" {
		t.Fatalf("unexpected: ok=%v v=%q", ok, string(b))
	}

	if err := st.Delete(ctx, "b", "k"); err != nil {
		t.Fatal(err)
	}
	_, ok, err = st.Get(ctx, "b", "k")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("expected deleted")
	}

	// Ensure files are written under baseDir
	if _, err := os.Stat(filepath.Join(dir, "data", "b")); err != nil {
		t.Fatalf("expected bucket dir: %v", err)
	}
}
