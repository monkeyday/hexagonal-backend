package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryCache_SetAndGet(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		key       string
		value     any
		wantFound bool
	}{
		{name: "string value", key: "k1", value: "hello", wantFound: true},
		{name: "int value", key: "k2", value: 42, wantFound: true},
		{name: "missing key", key: "missing", value: nil, wantFound: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewMemoryCache()
			t.Cleanup(c.Close)
			if tc.value != nil {
				c.Set(ctx, tc.key, tc.value, nil)
			}
			ok := c.Get(ctx, tc.key, nil)
			if ok != tc.wantFound {
				t.Fatalf("Get(%q) found=%v, want %v", tc.key, ok, tc.wantFound)
			}
		})
	}
}

func TestMemoryCache_SetWithTTL(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		ttl       time.Duration
		sleep     time.Duration
		wantFound bool
	}{
		{
			name:      "future TTL — value retrievable",
			ttl:       10 * time.Second,
			sleep:     0,
			wantFound: true,
		},
		{
			name:      "expired TTL — value not returned",
			ttl:       time.Millisecond,
			sleep:     5 * time.Millisecond,
			wantFound: false,
		},
		{
			name:      "zero TTL — treated as no expiry",
			ttl:       0,
			sleep:     0,
			wantFound: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewMemoryCache()
			t.Cleanup(c.Close)
			c.Set(ctx, "key", "value", &tc.ttl)
			if tc.sleep > 0 {
				time.Sleep(tc.sleep)
			}
			ok := c.Get(ctx, "key", nil)
			if ok != tc.wantFound {
				t.Fatalf("Get found=%v, want %v", ok, tc.wantFound)
			}
		})
	}
}

func TestMemoryCache_IncrWindowResetsAfterExpiry(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache()
	t.Cleanup(c.Close)

	// Saturate the counter inside a short window, then let it expire.
	window := time.Millisecond
	for range 5 {
		c.IncrWindow(ctx, "key", window)
	}
	time.Sleep(5 * time.Millisecond)

	// First increment after expiry must return 1, not continue from 6.
	n, err := c.IncrWindow(ctx, "key", time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("IncrWindow after expiry = %d, want 1", n)
	}
}

func TestMemoryCache_IncrWindowWRONGTYPE(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache()
	t.Cleanup(c.Close)
	c.Set(ctx, "key", "not-an-int", nil)

	_, err := c.IncrWindow(ctx, "key", time.Minute)
	if err == nil {
		t.Fatal("expected WRONGTYPE error, got nil")
	}

	// original value must be untouched
	var got string
	if !c.Get(ctx, "key", &got) {
		t.Fatal("key should still exist after failed Incr")
	}
	if got != "not-an-int" {
		t.Fatalf("value corrupted: got %q, want %q", got, "not-an-int")
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache()
	t.Cleanup(c.Close)
	c.Set(ctx, "key", "value", nil)
	c.Delete(ctx, "key")
	if ok := c.Get(ctx, "key", nil); ok {
		t.Fatal("expected key to be deleted, but Get returned it")
	}
}

func TestMemoryCache_ExpiredGetDeletesItem(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache()
	t.Cleanup(c.Close)

	ttl := time.Millisecond
	c.Set(ctx, "key", "value", &ttl)
	time.Sleep(5 * time.Millisecond)

	if ok := c.Get(ctx, "key", nil); ok {
		t.Fatal("expected expired key to be missing")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.items["key"]; ok {
		t.Fatal("expired key should be deleted on read")
	}
}

func TestMemoryCache_JanitorSweepDeletesExpired(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache()
	t.Cleanup(c.Close)

	ttl := time.Millisecond
	c.Set(ctx, "expired", "value", &ttl)
	c.Set(ctx, "permanent", "value", nil)

	c.deleteExpired(time.Now().Add(time.Second))

	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.items["expired"]; ok {
		t.Fatal("sweep should delete the expired key")
	}
	if _, ok := c.items["permanent"]; !ok {
		t.Fatal("sweep must not delete keys without a TTL")
	}
}
