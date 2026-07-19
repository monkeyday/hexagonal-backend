package middleware

import (
	coreweb "sc/core/web"

	"github.com/gin-gonic/gin"
)

// CookieSecureKey is re-exported here so callers in this package can reference it
// without importing core/web directly.
const CookieSecureKey = coreweb.CookieSecureKey

func CookieSecure(enabled bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(CookieSecureKey, enabled)
		ctx.Next()
	}
}
