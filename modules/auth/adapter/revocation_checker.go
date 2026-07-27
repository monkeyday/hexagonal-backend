package adapter

import (
	"context"

	corecache "sc/core/cache"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
)

// revocationChecker adapts the revocation cache to the delivery layer's
// middleware.RevocationChecker port, reading the markers written by the
// revoking use cases (define.BlacklistKey / define.RevokedGrantKey).
type revocationChecker struct {
	cache corecache.ReadErrorCache
}

func newRevocationChecker(c corecache.ReadErrorCache) *revocationChecker {
	return &revocationChecker{cache: c}
}

func (r *revocationChecker) IsRevoked(ctx context.Context, jti string, grantID string) (bool, error) {
	revoked, err := r.cache.GetErr(ctx, define.BlacklistKey(jti), nil)
	if err != nil || revoked {
		return revoked, err
	}
	if grantID != "" {
		return r.cache.GetErr(ctx, define.RevokedGrantKey(entity.GrantID(grantID)), nil)
	}
	return false, nil
}
