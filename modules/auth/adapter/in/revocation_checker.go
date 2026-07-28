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
	// Inclusive on purpose. The marker and `iat` both carry Unix *seconds*, so within the
	// second the reset landed in there is no way to tell whether a token was signed before
	// or after it. A password reset is a security event, so the ambiguous case fails closed:
	// `<` would instead keep a pre-reset token alive for up to MaxTokenExpirySecs. The cost
	// is a sub-second window where a fresh login succeeds but its token is refused; retrying
	// past that second works. If immediate post-reset login ever has to work, the fix is
	// finer resolution or an explicit epoch — not relaxing this comparison
	// (grant-linkage.md §9).
	return found && claims.IssuedAt.Unix() <= invalidatedAt, nil
}
