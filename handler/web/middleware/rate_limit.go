package middleware

import (
	"fmt"
	"net/http"
	corecache "sc/core/cache"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
)

const rateLimitCacheKey = "ratelimit:%s"

// DistributedRateLimit returns a middleware that allows limit requests per window
// per client IP using the provided cache (Redis).
func DistributedRateLimit(c corecache.Cache, limit int64, window time.Duration) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ip := ctx.RemoteIP()
		if ip == "" {
			ctx.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"msg": "too many requests",
			})
			return
		}
		key := fmt.Sprintf(rateLimitCacheKey, ip)
		requestCtx := ctx.Request.Context()
		count, err := c.Incr(requestCtx, key)
		if err != nil {
			if isFailClosedPath(ctx.FullPath()) {
				ctx.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"msg": "too many requests",
				})
				return
			}
			ctx.Next() // fail open if cache is down
			return
		}

		if count == 1 {
			_ = c.Expire(requestCtx, key, window)
		}

		if count > limit {
			ctx.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"msg": "too many requests",
			})
			return
		}
		ctx.Next()
	}
}

func isFailClosedPath(path string) bool {
	return slices.Contains([]string{"/sign-in", "/token", "/protocol/openid-connect/token"}, path)
}
