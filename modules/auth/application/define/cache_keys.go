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
	// BlacklistKey and RevokedGrantKey are the only way to build them.
	blacklistCacheKey    = "blacklist:%s"
	revokedGrantCacheKey = "revoked_grant:%s"
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
