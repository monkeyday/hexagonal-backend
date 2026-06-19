package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	RequestIDKey    = "request_id"
	RequestIDHeader = "X-Request-Id"

	// maxInboundRequestID bounds a client-supplied id so it cannot bloat logs;
	// anything longer is replaced with a freshly generated id.
	maxInboundRequestID = 128
)

// RequestID assigns a request id to every request: it honors a reasonable
// inbound X-Request-Id (so a trace survives across hops) or generates one,
// exposes it on the gin context for logging, and echoes it in the response.
func RequestID() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		id := ctx.GetHeader(RequestIDHeader)
		if id == "" || len(id) > maxInboundRequestID {
			id = uuid.NewString()
		}
		ctx.Set(RequestIDKey, id)
		ctx.Header(RequestIDHeader, id)
		ctx.Next()
	}
}
