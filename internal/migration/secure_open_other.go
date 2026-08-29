//go:build !linux

package migration

import "os"

// Production packages target Linux and use openat2.  This fallback exists so
// platform-independent parsing and policy tests can still run on developer
// workstations; the stable inode checks in readStableRegularFile remain active.
func openNoSymlink(path string) (*os.File, error) {
	return os.Open(path)
}

func openWritableNoSymlink(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY, 0)
}

func unlinkSameFileNoSymlink(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || expected == nil || !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return os.ErrInvalid
	}
	return os.Remove(path)
}

func removeTreeBeneath(_, _ string) error {
	return os.ErrInvalid
}
