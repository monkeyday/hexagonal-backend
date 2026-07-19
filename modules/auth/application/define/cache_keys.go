package define

const (
	AuthorizeRequestCacheKey = "auth:request:%s"
	AuthCodeCacheKey         = "auth:code:%s"
	BlacklistCacheKey        = "blacklist:%s"
	// ForgotPasswordRateKey is keyed by a hash of the email so plaintext addresses
	// never land in cache keys (see email-encryption policy).
	ForgotPasswordRateKey = "pwreset:rl:%s"
)
