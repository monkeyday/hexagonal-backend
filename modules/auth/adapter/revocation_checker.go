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

func (r *revocationChecker) IsRevoked(ctx context.Context, jti string, grantID string) (bool, error) {
	revoked, err := r.cache.GetErr(ctx, fmt.Sprintf(define.BlacklistCacheKey, jti), nil)
	if err != nil || revoked {
		return revoked, err
	}
	if grantID != "" {
		return r.cache.GetErr(ctx, fmt.Sprintf(define.RevokedGrantCacheKey, grantID), nil)
	}
	return false, nil
}
