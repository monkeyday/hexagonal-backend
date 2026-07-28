package define

import (
	"fmt"

	"sc/modules/auth/domain/entity"
)

const (
	AuthorizeRequestCacheKey = "auth:request:%s"
	AuthCodeCacheKey         = "auth:code:%s"
	// ForgotPasswordRateKey is keyed by a hash of the email so plaintext addresses
	// never land in cache keys (see email-encryption policy).
	ForgotPasswordRateKey = "pwreset:rl:%s"

	// The revocation key formats stay unexported so no caller can hand-roll a key:
	// BlacklistKey, RevokedGrantKey and SessionsInvalidatedKey are the only way to build them.
	blacklistCacheKey           = "blacklist:%s"
	revokedGrantCacheKey        = "revoked_grant:%s"
	sessionsInvalidatedCacheKey = "sessions_invalidated:%s"
)

// BlacklistKey marks a single access token as revoked; jti = the token's `jti` claim.
func BlacklistKey(jti string) string {
	return fmt.Sprintf(blacklistCacheKey, jti)
}

// RevokedGrantKey marks an entire grant as revoked, so the stateless access tokens
// issued under it stop verifying; grantID = the `sid` claim (grant-linkage.md §5).
func RevokedGrantKey(grantID entity.GrantID) string {
	return fmt.Sprintf(revokedGrantCacheKey, grantID)
}

// SessionsInvalidatedKey marks every access token a user held before the given instant as
// revoked, whatever grant issued it; userID = the `sub` claim (grant-linkage.md §9).
func SessionsInvalidatedKey(userID entity.UserID) string {
	return fmt.Sprintf(sessionsInvalidatedCacheKey, userID)
}
