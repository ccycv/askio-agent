//go:build linux

package migration

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func openDirectoryAt(dirFD int, path string, resolve uint64) (int, error) {
	return unix.Openat2(dirFD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: resolve,
	})
}

func sameInode(left, right *unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func removeDirectoryContents(dirFD int, rootDevice uint64) error {
	duplicate, err := unix.Dup(dirFD)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(duplicate), "migration-cleanup-directory")
	if directory == nil {
		_ = unix.Close(duplicate)
		return errors.New("open cleanup directory descriptor")
	}
	entries, err := directory.ReadDir(-1)
	_ = directory.Close()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." {
			return errors.New("unsafe cleanup directory entry")
		}
		var before unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		if before.Dev != rootDevice {
			return errors.New("cleanup entry crosses a filesystem boundary")
		}
		if before.Mode&unix.S_IFMT == unix.S_IFDIR {
			childFD, err := openDirectoryAt(dirFD, name, uint64(unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_XDEV))
			if err != nil {
				return err
			}
			var opened unix.Stat_t
			if err := unix.Fstat(childFD, &opened); err != nil {
				_ = unix.Close(childFD)
				return err
			}
			if !sameInode(&before, &opened) {
				_ = unix.Close(childFD)
				return errors.New("cleanup directory changed while opening")
			}
			if err := removeDirectoryContents(childFD, rootDevice); err != nil {
				_ = unix.Close(childFD)
				return err
			}
			_ = unix.Close(childFD)
			var after unix.Stat_t
			if err := unix.Fstatat(dirFD, name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameInode(&before, &after) {
				return errors.New("cleanup directory changed before removal")
			}
			if err := unix.Unlinkat(dirFD, name, unix.AT_REMOVEDIR); err != nil {
				return err
			}
			continue
		}
		if err := unix.Unlinkat(dirFD, name, 0); err != nil {
			return err
		}
	}
	return nil
}

// removeTreeBeneath removes one direct staging child without ever resolving a
// pathname after it has been opened. Every recursive operation is relative to
// an owned descriptor and rejects symlinks, magic links, and mount crossings.
func removeTreeBeneath(root, leaf string) error {
	if leaf == "" || leaf == "." || leaf == ".." || filepath.Base(leaf) != leaf {
		return errors.New("cleanup leaf is invalid")
	}
	rootFD, err := openDirectoryAt(unix.AT_FDCWD, root, uint64(unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS))
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return err
	}
	var before unix.Stat_t
	if err := unix.Fstatat(rootFD, leaf, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFDIR || before.Dev != rootStat.Dev {
		return errors.New("cleanup target is not a directory on the allowed filesystem")
	}
	childFD, err := openDirectoryAt(rootFD, leaf, uint64(unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_XDEV))
	if err != nil {
		return err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(childFD, &opened); err != nil {
		_ = unix.Close(childFD)
		return err
	}
	if !sameInode(&before, &opened) {
		_ = unix.Close(childFD)
		return errors.New("cleanup target changed while opening")
	}
	if err := removeDirectoryContents(childFD, rootStat.Dev); err != nil {
		_ = unix.Close(childFD)
		return err
	}
	_ = unix.Close(childFD)
	var after unix.Stat_t
	if err := unix.Fstatat(rootFD, leaf, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameInode(&before, &after) {
		return errors.New("cleanup target changed before removal")
	}
	return unix.Unlinkat(rootFD, leaf, unix.AT_REMOVEDIR)
}

// openNoSymlink resolves no symbolic or magic-link component.  Failure on a
// kernel without openat2 support is intentional: the root broker must not
// silently fall back to a pathname walk with a race window.
func openNoSymlink(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openWritableNoSymlink(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_WRONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func unlinkSameFileNoSymlink(path string, expected os.FileInfo) error {
	leaf := filepath.Base(path)
	parent := filepath.Dir(path)
	if leaf == "" || leaf == "." || leaf == ".." || expected == nil {
		return errors.New("cleanup file path is invalid")
	}
	expectedStat, ok := expected.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cleanup file identity is unavailable")
	}
	parentFD, err := openDirectoryAt(unix.AT_FDCWD, parent, uint64(unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS))
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, leaf, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if expectedStat.Dev != current.Dev || expectedStat.Ino != current.Ino || current.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("cleanup file changed before removal")
	}
	return unix.Unlinkat(parentFD, leaf, 0)
}
