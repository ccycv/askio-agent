//go:build linux

package migration

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRemoveTreeBeneathRemovesOnlyDescriptorBoundChild(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "must-survive")
	if err := os.WriteFile(sentinel, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "staging")
	if err := os.MkdirAll(filepath.Join(target, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "nested", "payload"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeBeneath(root, "staging"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging target survived descriptor cleanup: %v", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "safe" {
		t.Fatalf("cleanup followed a symlink outside its root: %q %v", data, err)
	}
}

func TestRemoveTreeBeneathRejectsRootSwapToSymlink(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	out := t.TempDir()
	sentinel := filepath.Join(out, "must-survive")
	if err := os.WriteFile(sentinel, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, root); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeBeneath(root, "must-survive"); err == nil {
		t.Fatal("symlink root was accepted")
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "safe" {
		t.Fatalf("root symlink escaped descriptor cleanup: %q %v", data, err)
	}
}

func TestRemoveTreeBeneathNeverFollowsContinuouslySwappedLeaf(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	sentinel := filepath.Join(out, "must-survive")
	if err := os.WriteFile(sentinel, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "staging")
	spare := filepath.Join(root, "spare")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			_ = os.Rename(target, spare)
			_ = os.Symlink(out, target)
			_ = os.Remove(target)
			_ = os.Rename(spare, target)
			_ = os.Mkdir(target, 0o700)
		}
	}()
	for index := 0; index < 200; index++ {
		_ = removeTreeBeneath(root, "staging")
		_ = os.Mkdir(target, 0o700)
	}
	stop.Store(true)
	<-done
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "safe" {
		t.Fatalf("continuous leaf swap escaped descriptor cleanup: %q %v", data, err)
	}
}
