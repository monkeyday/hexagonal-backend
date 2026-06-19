package middleware

import (
	"sc/core/web"

	"github.com/gin-gonic/gin"
)

// OAuth2Errors flags the request so the HTTP responder renders error responses
// in the RFC 6749 §5.2 shape ({"error","error_description"}). Apply it to the
// OAuth2 token/revoke/introspect endpoints.
func OAuth2Errors() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(web.OAuth2ErrorFormatKey, true)
		ctx.Next()
	}
}
