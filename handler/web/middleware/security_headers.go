package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	headerFrameOptions       = "X-Frame-Options"
	headerCSP                = "Content-Security-Policy"
	headerContentTypeOptions = "X-Content-Type-Options"
	headerReferrerPolicy     = "Referrer-Policy"
	headerCacheControl       = "Cache-Control"
	headerPragma             = "Pragma"

	frameOptionsDeny    = "DENY"
	cspFrameAncestors   = "frame-ancestors 'none'"
	contentTypeNoSniff  = "nosniff"
	referrerNoReferrer  = "no-referrer"
	cacheControlNoStore = "no-store"
	pragmaNoCache       = "no-cache"
)

// SecurityHeaders hardens every response: the sign-in/consent pages must not
// be frameable (clickjacking, a recognized OAuth attack), and token/error
// responses must never be cached (RFC 6749 §5.1). Cacheable endpoints
// (discovery, JWKS) override Cache-Control via CachePublic.
func SecurityHeaders() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := ctx.Writer.Header()
		h.Set(headerFrameOptions, frameOptionsDeny)
		h.Set(headerCSP, cspFrameAncestors)
		h.Set(headerContentTypeOptions, contentTypeNoSniff)
		h.Set(headerReferrerPolicy, referrerNoReferrer)
		h.Set(headerCacheControl, cacheControlNoStore)
		h.Set(headerPragma, pragmaNoCache)
		ctx.Next()
	}
}

// CachePublic overrides the default no-store for safely cacheable,
// non-sensitive endpoints such as discovery and JWKS.
func CachePublic(maxAge time.Duration) gin.HandlerFunc {
	value := fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds()))
	return func(ctx *gin.Context) {
		h := ctx.Writer.Header()
		h.Set(headerCacheControl, value)
		h.Del(headerPragma)
		ctx.Next()
	}
}
