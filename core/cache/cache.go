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
	// IncrWindow atomically increments the counter at key and guarantees it
	// carries a TTL: the window is applied on first increment and re-applied if
	// the key has somehow lost its TTL, so a counter can never persist forever.
	IncrWindow(ctx context.Context, key string, window time.Duration) (int64, error)
}
