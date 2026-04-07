package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// FileStore is a very small key-value store backed by files.
// It is used for caching remote config and persisting small bits of state.
//
// Layout:
//   <baseDir>/<bucket>/<key>
//
// Values are written atomically (write temp + rename).
type FileStore struct {
	baseDir string
}

func OpenFileStore(baseDir string) (*FileStore, error) {
	if baseDir == "" {
		baseDir = "./.askio-monitor"
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{baseDir: baseDir}, nil
}

func (s *FileStore) path(bucket, key string) string {
	return filepath.Join(s.baseDir, bucket, key)
}

func (s *FileStore) Put(ctx context.Context, bucket, key string, value []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	p := s.path(bucket, key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, value, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (s *FileStore) Get(ctx context.Context, bucket, key string) ([]byte, bool, error) {
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
	}
	p := s.path(bucket, key)
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

func (s *FileStore) Delete(ctx context.Context, bucket, key string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	p := s.path(bucket, key)
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

func (s *FileStore) Close() error { return nil }

// Debug helper.
func (s *FileStore) String() string {
	return fmt.Sprintf("FileStore(%s)", s.baseDir)
}
