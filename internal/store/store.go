package store

import "context"

type Store interface {
	Put(ctx context.Context, bucket, key string, value []byte) error
	Get(ctx context.Context, bucket, key string) ([]byte, bool, error)
	Delete(ctx context.Context, bucket, key string) error
	Close() error
}
