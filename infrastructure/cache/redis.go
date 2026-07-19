package cache

import (
	"context"
	"encoding/json"
	"errors"
	corecache "sc/core/cache"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisPingTimeout = 5 * time.Second

var _ corecache.Cache = (*RedisCache)(nil)

type RedisOptions struct {
	Addr     string
	Password string
	DB       int
}

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(opts RedisOptions) (*RedisCache, error) {
	c := redis.NewClient(&redis.Options{
		Addr:     opts.Addr,
		Password: opts.Password,
		DB:       opts.DB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), redisPingTimeout)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &RedisCache{client: c}, nil
}

func (r *RedisCache) Set(ctx context.Context, key string, value any, ttl *time.Duration) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	expiration := time.Duration(0)
	if ttl != nil {
		expiration = *ttl
	}
	return r.client.Set(ctx, key, b, expiration).Err()
}

func (r *RedisCache) Get(ctx context.Context, key string, dest any) bool {
	b, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		return false
	}
	if dest == nil {
		return true
	}
	return json.Unmarshal(b, dest) == nil
}

func (r *RedisCache) GetErr(ctx context.Context, key string, dest any) (bool, error) {
	b, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, err
	}
	if dest == nil {
		return true, nil
	}
	if err := json.Unmarshal(b, dest); err != nil {
		return false, err
	}
	return true, nil
}

func (r *RedisCache) GetAndDelete(ctx context.Context, key string, dest any) bool {
	b, err := r.client.GetDel(ctx, key).Bytes()
	if err != nil {
		return false
	}
	if dest == nil {
		return true
	}
	return json.Unmarshal(b, dest) == nil
}

func (r *RedisCache) Delete(ctx context.Context, key string) {
	r.client.Del(ctx, key)
}

// incrWindowScript increments and sets the TTL in one atomic round trip.
// The PTTL < 0 check covers both a fresh key and a key that lost its TTL
// (e.g. a past Expire failure), so a counter can never persist forever.
var incrWindowScript = redis.NewScript(`
local v = redis.call('INCR', KEYS[1])
if redis.call('PTTL', KEYS[1]) < 0 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return v`)

func (r *RedisCache) IncrWindow(ctx context.Context, key string, window time.Duration) (int64, error) {
	return incrWindowScript.Run(ctx, r.client, []string{key}, window.Milliseconds()).Int64()
}

func (r *RedisCache) Close() error {
	return r.client.Close()
}
