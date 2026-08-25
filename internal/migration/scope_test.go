package migration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScopeResolverRejectsTraversalAndSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	if err := os.MkdirAll(filepath.Join(root, "safe"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewScopeResolver(map[string]string{"workspace": root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("workspace", "../escape", true); err == nil {
		t.Fatal("traversal was accepted")
	}
	if _, err := resolver.Resolve("unknown", "safe", false); err == nil {
		t.Fatal("unknown handle was accepted")
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve("workspace", "link/file", true); err == nil {
		t.Fatal("symlink traversal was accepted")
	}
	resolved, err := resolver.Resolve("workspace", "safe/file", true)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != filepath.Join(root, "safe", "file") {
		t.Fatalf("unexpected resolved path: %s", resolved)
	}
}
