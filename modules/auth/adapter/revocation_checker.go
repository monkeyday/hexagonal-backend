package adapter

import (
	"context"
	"fmt"

	corecache "sc/core/cache"
	"sc/modules/auth/application/define"
)

// revocationChecker adapts the blacklist cache to the delivery layer's
// middleware.RevocationChecker port. It owns the module's blacklist key convention.
type revocationChecker struct {
	cache corecache.ReadErrorCache
}

func newRevocationChecker(c corecache.ReadErrorCache) *revocationChecker {
	return &revocationChecker{cache: c}
}

func (r *revocationChecker) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return r.cache.GetErr(ctx, fmt.Sprintf(define.BlacklistCacheKey, jti), nil)
}
