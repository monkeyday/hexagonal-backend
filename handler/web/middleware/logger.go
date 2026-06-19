package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const loggerKey = "logger"

func Logger() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		base := log.Logger
		logger := base.With().
			Str(RequestIDKey, ctx.GetString(RequestIDKey)).
			Str("method", ctx.Request.Method).
			Str("host", ctx.Request.Host).
			Str("path", ctx.Request.URL.Path).
			Str("query", ctx.Request.URL.RawQuery).
			Str("user_agent", ctx.Request.UserAgent()).
			Str("referer", ctx.Request.Referer()).
			Logger()
		ctx.Set(loggerKey, &logger)

		start := time.Now()
		ctx.Next()
		elapsed := time.Since(start)
		status := ctx.Writer.Status()

		event := logger.Info().
			Int("status", status).
			Dur("latency", elapsed)
		if location := ctx.Writer.Header().Get("Location"); location != "" {
			event = event.Str("location", location)
		}
		event.Msg("handled request")
	}
}
