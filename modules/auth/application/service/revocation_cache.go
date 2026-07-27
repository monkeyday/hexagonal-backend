package service

import (
	"context"
	"time"

	corecache "sc/core/cache"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
)

// RevocationCache writes the two revocation markers the token layer reads:
// a per-token blacklist entry and a per-grant marker. It owns the pairing of
// each marker with its TTL, so no call site can store one with the wrong
// lifetime. Callers keep their own error policy — every method returns the
// cache error and logs nothing.
type RevocationCache struct {
	cache corecache.Cache
}

// NewRevocationCache returns nil when no cache is configured. Callers that treat
// marker writes as best-effort (the refresh replay path) nil-check the
// collaborator; callers that require a cache dereference it, so a wiring bug
// surfaces immediately instead of silently skipping revocation.
func NewRevocationCache(cache corecache.Cache) *RevocationCache {
	if cache == nil {
		return nil
	}
	return &RevocationCache{cache: cache}
}

// BlacklistJTI marks one access token revoked until its own expiry — past that
// point the token fails verification on its own.
func (s *RevocationCache) BlacklistJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.cache.Set(ctx, define.BlacklistKey(jti), true, new(time.Until(expiresAt)))
}

// MarkGrantRevoked marks a whole grant revoked. The TTL outlives any access token
// that could have been issued under the grant, so the cascade check cannot expire
// early (define.RevokedGrantMarkerTTL).
func (s *RevocationCache) MarkGrantRevoked(ctx context.Context, grantID entity.GrantID) error {
	return s.cache.Set(ctx, define.RevokedGrantKey(grantID), true, new(define.RevokedGrantMarkerTTL))
}
