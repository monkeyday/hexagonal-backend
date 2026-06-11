package dependencies

import (
	"errors"
	"strings"
	"testing"

	corecache "sc/core/cache"
	"sc/infrastructure/cache"
)

func TestSelectCache(t *testing.T) {
	t.Run("no Redis configured — memory cache", func(t *testing.T) {
		c, err := selectCache("", func() (corecache.Cache, error) {
			t.Fatal("redis constructor must not be called when no addr is configured")
			return nil, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := c.(*cache.MemoryCache); !ok {
			t.Errorf("got %T, want *cache.MemoryCache", c)
		}
	})

	t.Run("Redis configured but unreachable — fail closed", func(t *testing.T) {
		_, err := selectCache("redis.internal:6379", func() (corecache.Cache, error) {
			return nil, errors.New("dial tcp: connection refused")
		})
		if err == nil {
			t.Fatal("expected error when configured Redis is unreachable")
		}
		if !strings.Contains(err.Error(), "redis.internal:6379") {
			t.Errorf("error should name the configured address, got: %v", err)
		}
	})

	t.Run("Redis configured and reachable — redis cache used", func(t *testing.T) {
		want := cache.NewMemoryCache() // stand-in instance; only identity matters
		t.Cleanup(want.Close)
		c, err := selectCache("redis.internal:6379", func() (corecache.Cache, error) {
			return want, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c != corecache.Cache(want) {
			t.Error("selectCache must return the constructed cache")
		}
	})
}
