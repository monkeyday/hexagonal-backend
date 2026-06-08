package cache

import (
	"context"
	"encoding/json"
	"fmt"
	corecache "sc/core/cache"
	"sync"
	"time"
)

var _ corecache.Cache = (*MemoryCache)(nil)

type cacheItem struct {
	value     any
	expiresAt time.Time // zero value means no expiry
}

type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{items: make(map[string]cacheItem)}
}

func (c *MemoryCache) Set(_ context.Context, key string, value any, ttl *time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := cacheItem{value: value}
	if ttl != nil && *ttl > 0 {
		item.expiresAt = time.Now().Add(*ttl)
	}
	c.items[key] = item
	return nil
}

func (c *MemoryCache) Get(_ context.Context, key string, dest any) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	if !ok || (!item.expiresAt.IsZero() && time.Now().After(item.expiresAt)) {
		return false
	}
	if dest == nil {
		return true
	}
	b, err := json.Marshal(item.value)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, dest) == nil
}

func (c *MemoryCache) GetErr(_ context.Context, key string, dest any) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	if !ok || (!item.expiresAt.IsZero() && time.Now().After(item.expiresAt)) {
		return false, nil
	}
	if dest == nil {
		return true, nil
	}
	b, err := json.Marshal(item.value)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, dest); err != nil {
		return false, err
	}
	return true, nil
}

func (c *MemoryCache) GetAndDelete(_ context.Context, key string, dest any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if !ok || (!item.expiresAt.IsZero() && time.Now().After(item.expiresAt)) {
		if ok {
			delete(c.items, key)
		}
		return false
	}
	delete(c.items, key)
	if dest == nil {
		return true
	}
	b, err := json.Marshal(item.value)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, dest) == nil
}

func (c *MemoryCache) Delete(_ context.Context, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *MemoryCache) Incr(_ context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if ok {
		if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
			item = cacheItem{}
		} else if _, ok := item.value.(int64); !ok {
			return 0, fmt.Errorf("WRONGTYPE operation against key holding non-integer value")
		}
	}
	var val int64
	if v, ok := item.value.(int64); ok {
		val = v
	}
	val++
	item.value = val
	c.items[key] = item
	return val, nil
}

func (c *MemoryCache) Expire(_ context.Context, key string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if item, ok := c.items[key]; ok {
		item.expiresAt = time.Now().Add(ttl)
		c.items[key] = item
	}
	return nil
}
