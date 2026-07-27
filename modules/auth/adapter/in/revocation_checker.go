package adapter

import (
	"context"

	corecache "sc/core/cache"
	corejwt "sc/core/jwt"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
)

// revocationChecker adapts the revocation cache to the delivery layer's
// middleware.RevocationChecker port, reading the markers written by the
// revoking use cases (define.BlacklistKey / define.RevokedGrantKey /
// define.SessionsInvalidatedKey).
type revocationChecker struct {
	cache corecache.ReadErrorCache
}

func newRevocationChecker(c corecache.ReadErrorCache) *revocationChecker {
	return &revocationChecker{cache: c}
}

func (r *revocationChecker) IsRevoked(ctx context.Context, claims *corejwt.Claims) (bool, error) {
	revoked, err := r.cache.GetErr(ctx, define.BlacklistKey(claims.ID), nil)
	if err != nil || revoked {
		return revoked, err
	}
	if claims.GrantID != "" {
		grantRevoked, err := r.cache.GetErr(ctx, define.RevokedGrantKey(entity.GrantID(claims.GrantID)), nil)
		if err != nil || grantRevoked {
			return grantRevoked, err
		}
	}
	// A token with no iat cannot be placed relative to the invalidation instant, so the
	// user-level layer is skipped — the same expand/contract treatment an empty sid gets.
	if claims.IssuedAt == nil {
		return false, nil
	}
	var invalidatedAt int64
	found, err := r.cache.GetErr(ctx, define.SessionsInvalidatedKey(entity.UserID(claims.Subject)), &invalidatedAt)
	if err != nil {
		return false, err
	}
	// Inclusive: a token stamped in the same second as the invalidation is rejected rather
	// than admitted (grant-linkage.md §9, clock skew).
	return found && claims.IssuedAt.Unix() <= invalidatedAt, nil
}
