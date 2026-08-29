package migration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var errUnsafeScope = errors.New("migration resource scope is unsafe")

type ScopeResolver struct {
	roots map[string]string
}

func (s *ScopeResolver) Root(handle string) (string, error) {
	root, ok := s.roots[handle]
	if !ok {
		return "", fmt.Errorf("%w: unknown root handle", errUnsafeScope)
	}
	return root, nil
}

func NewScopeResolver(roots map[string]string) (*ScopeResolver, error) {
	if len(roots) == 0 {
		return nil, errors.New("at least one migration root handle is required")
	}
	copyRoots := make(map[string]string, len(roots))
	for handle, root := range roots {
		clean := filepath.Clean(root)
		if handle == "" || !filepath.IsAbs(clean) || clean == "/" || clean != root {
			return nil, fmt.Errorf("%w: invalid root handle %q", errUnsafeScope, handle)
		}
		info, err := os.Lstat(clean)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: root handle %q is missing, not a directory, or a symlink", errUnsafeScope, handle)
		}
		copyRoots[handle] = clean
	}
	return &ScopeResolver{roots: copyRoots}, nil
}

func cleanRelative(value string) (string, error) {
	if value == "" || value == "." {
		return ".", nil
	}
	if filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
		return "", errUnsafeScope
	}
	clean := filepath.Clean(value)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errUnsafeScope
	}
	return clean, nil
}

// Resolve returns a path below a preconfigured handle. Existing symlink path
// components are rejected so a task cannot redirect an allowlisted root.
func (s *ScopeResolver) Resolve(handle, relative string, allowMissingLeaf bool) (string, error) {
	root, ok := s.roots[handle]
	if !ok {
		return "", fmt.Errorf("%w: unknown root handle", errUnsafeScope)
	}
	cleanRelativePath, err := cleanRelative(relative)
	if err != nil {
		return "", err
	}
	target := filepath.Join(root, cleanRelativePath)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errUnsafeScope
	}
	current := root
	parts := strings.Split(rel, string(filepath.Separator))
	for index, part := range parts {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) && allowMissingLeaf && index == len(parts)-1 {
			continue
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: symlink component rejected", errUnsafeScope)
		}
	}
	return target, nil
}
