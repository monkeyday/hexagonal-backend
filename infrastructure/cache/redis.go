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

func (r *RedisCache) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

func (r *RedisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return r.client.Expire(ctx, key, ttl).Err()
}

func (r *RedisCache) Close() error {
	return r.client.Close()
}
