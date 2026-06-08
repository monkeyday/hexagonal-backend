package cache

import (
	"context"
	"time"
)

// ReadErrorCache distinguishes a cache miss (false, nil) from a read failure (false, err).
// Use it where a cache error must be treated as a security boundary (e.g. token blacklist checks).
type ReadErrorCache interface {
	GetErr(ctx context.Context, key string, dest any) (bool, error)
}

type Cache interface {
	ReadErrorCache

	Set(ctx context.Context, key string, value any, ttl *time.Duration) error
	Get(ctx context.Context, key string, dest any) bool
	GetAndDelete(ctx context.Context, key string, dest any) bool
	Delete(ctx context.Context, key string)
	Incr(ctx context.Context, key string) (int64, error)
	// Expire sets a TTL on an existing key. Zero or negative TTL expires the key
	// immediately (or effectively immediately — callers must not rely on exact timing).
	// No-ops silently if the key does not exist.
	Expire(ctx context.Context, key string, ttl time.Duration) error
}
