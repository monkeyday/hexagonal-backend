package cache

import (
	"context"
	"os"
	corecache "sc/core/cache"
	"strconv"
	"testing"
	"time"
)

// These durations give Redis enough room to honor a PEXPIRE over the wire
// without making the suite slow; the memory cache expires lazily so it is not
// sensitive to them.
const (
	ttlExpiry   = 50 * time.Millisecond
	waitPastTTL = 200 * time.Millisecond
)

type cachePayload struct {
	Code   string `json:"code"`
	UserID string `json:"user_id"`
}

// runCacheContract exercises the behaviour every corecache.Cache implementation
// must share. newCache returns a fresh, empty cache for each subtest so the
// drivers (memory, redis) stay isolated. This is the parity harness: memory and
// redis run the identical assertions.
func runCacheContract(t *testing.T, newCache func(t *testing.T) corecache.Cache) {
	ctx := context.Background()

	t.Run("Set then Get round-trips a value", func(t *testing.T) {
		c := newCache(t)
		want := cachePayload{Code: "abc123", UserID: "user-1"}
		if err := c.Set(ctx, "k", want, nil); err != nil {
			t.Fatalf("Set: %v", err)
		}
		var got cachePayload
		if ok := c.Get(ctx, "k", &got); !ok {
			t.Fatal("Get: key not found")
		}
		if got != want {
			t.Errorf("Get = %+v, want %+v", got, want)
		}
	})

	t.Run("Get on missing key returns false", func(t *testing.T) {
		c := newCache(t)
		var got cachePayload
		if ok := c.Get(ctx, "missing", &got); ok {
			t.Error("Get on missing key returned true")
		}
	})

	t.Run("Get with nil dest is an existence check", func(t *testing.T) {
		c := newCache(t)
		if err := c.Set(ctx, "k", "v", nil); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if ok := c.Get(ctx, "k", nil); !ok {
			t.Error("Get(nil dest) on present key returned false")
		}
		if ok := c.Get(ctx, "missing", nil); ok {
			t.Error("Get(nil dest) on missing key returned true")
		}
	})

	t.Run("GetErr distinguishes a hit from a miss", func(t *testing.T) {
		c := newCache(t)
		ok, err := c.GetErr(ctx, "missing", nil)
		if err != nil {
			t.Fatalf("GetErr miss: unexpected error %v", err)
		}
		if ok {
			t.Error("GetErr miss returned ok=true")
		}

		if err := c.Set(ctx, "k", cachePayload{Code: "x", UserID: "u"}, nil); err != nil {
			t.Fatalf("Set: %v", err)
		}
		var got cachePayload
		ok, err = c.GetErr(ctx, "k", &got)
		if err != nil {
			t.Fatalf("GetErr hit: unexpected error %v", err)
		}
		if !ok || got.Code != "x" {
			t.Errorf("GetErr hit = (%v, %+v), want (true, code x)", ok, got)
		}
	})

	t.Run("Set with TTL expires the value", func(t *testing.T) {
		c := newCache(t)
		ttl := ttlExpiry
		if err := c.Set(ctx, "k", "v", &ttl); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if ok := c.Get(ctx, "k", nil); !ok {
			t.Fatal("value should be present before TTL elapses")
		}
		time.Sleep(waitPastTTL)
		if ok := c.Get(ctx, "k", nil); ok {
			t.Error("value should be gone after TTL elapses")
		}
	})

	t.Run("Set with nil TTL never expires", func(t *testing.T) {
		c := newCache(t)
		if err := c.Set(ctx, "k", "v", nil); err != nil {
			t.Fatalf("Set: %v", err)
		}
		time.Sleep(waitPastTTL)
		if ok := c.Get(ctx, "k", nil); !ok {
			t.Error("value with no TTL should persist")
		}
	})

	t.Run("GetAndDelete returns then removes the value", func(t *testing.T) {
		c := newCache(t)
		if err := c.Set(ctx, "k", cachePayload{Code: "once", UserID: "u"}, nil); err != nil {
			t.Fatalf("Set: %v", err)
		}
		var got cachePayload
		if ok := c.GetAndDelete(ctx, "k", &got); !ok || got.Code != "once" {
			t.Fatalf("GetAndDelete = (%v, %+v), want (true, code once)", ok, got)
		}
		if ok := c.Get(ctx, "k", nil); ok {
			t.Error("key should be gone after GetAndDelete")
		}
	})

	t.Run("GetAndDelete on missing key returns false", func(t *testing.T) {
		c := newCache(t)
		if ok := c.GetAndDelete(ctx, "missing", nil); ok {
			t.Error("GetAndDelete on missing key returned true")
		}
	})

	t.Run("Delete removes a key", func(t *testing.T) {
		c := newCache(t)
		if err := c.Set(ctx, "k", "v", nil); err != nil {
			t.Fatalf("Set: %v", err)
		}
		c.Delete(ctx, "k")
		if ok := c.Get(ctx, "k", nil); ok {
			t.Error("key should be gone after Delete")
		}
	})

	t.Run("IncrWindow increments and carries a TTL that resets the counter", func(t *testing.T) {
		c := newCache(t)
		window := ttlExpiry
		if n, err := c.IncrWindow(ctx, "counter", window); err != nil || n != 1 {
			t.Fatalf("IncrWindow #1 = (%d, %v), want (1, nil)", n, err)
		}
		if n, err := c.IncrWindow(ctx, "counter", window); err != nil || n != 2 {
			t.Fatalf("IncrWindow #2 = (%d, %v), want (2, nil)", n, err)
		}
		time.Sleep(waitPastTTL)
		if n, err := c.IncrWindow(ctx, "counter", window); err != nil || n != 1 {
			t.Fatalf("IncrWindow after window = (%d, %v), want (1, nil) — TTL must reset the counter", n, err)
		}
	})
}

func TestMemoryCache_Contract(t *testing.T) {
	runCacheContract(t, func(t *testing.T) corecache.Cache {
		c := NewMemoryCache()
		t.Cleanup(c.Close)
		return c
	})
}

func TestRedisCache_Contract(t *testing.T) {
	c := requireRedis(t)
	runCacheContract(t, func(t *testing.T) corecache.Cache {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.client.FlushDB(ctx).Err(); err != nil {
			t.Fatalf("FlushDB: %v", err)
		}
		return c
	})
}

// requireRedis connects to a Redis instance for parity tests, or skips when
// none is configured. It targets a dedicated test DB and flushes it on cleanup
// so it never leaves keys behind. Honors REDIS_TEST_* overrides, falling back
// to the same REDIS_* vars the server reads.
func requireRedis(t *testing.T) *RedisCache {
	t.Helper()

	addr := firstNonEmpty(os.Getenv("REDIS_TEST_ADDR"), os.Getenv("REDIS_ADDR"))
	if addr == "" {
		t.Skip("set REDIS_ADDR (or REDIS_TEST_ADDR) to run Redis parity tests")
	}

	db := 0
	if raw := firstNonEmpty(os.Getenv("REDIS_TEST_DB"), os.Getenv("REDIS_DB")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid REDIS_DB %q: %v", raw, err)
		}
		db = n
	}

	c, err := NewRedisCache(RedisOptions{
		Addr:     addr,
		Password: firstNonEmpty(os.Getenv("REDIS_TEST_PASSWORD"), os.Getenv("REDIS_PASSWORD")),
		DB:       db,
	})
	if err != nil {
		t.Fatalf("connect redis at %s: %v", addr, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.client.FlushDB(ctx)
		c.Close()
	})
	return c
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
