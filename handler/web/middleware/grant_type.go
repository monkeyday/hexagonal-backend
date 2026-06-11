package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	coreerror "sc/core/error"
	"sc/handler/web/responder"
	"slices"

	"github.com/gin-gonic/gin"
)

const GrantTypeKey = "grant_type"
const maxGrantTypeBodyBytes = 1 << 20

func GrantType(allowed []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		gt := ctx.PostForm(GrantTypeKey)
		if gt == "" {
			gt = jsonGrantType(ctx)
		}
		if gt == "" {
			res := responder.NewHTTPResponder(ctx)
			res.Response(nil, coreerror.New(coreerror.BadRequest, http.StatusBadRequest, "grant_type is required"), false)
			ctx.Abort()
			return
		}
		if len(allowed) > 0 && !slices.Contains(allowed, gt) {
			res := responder.NewHTTPResponder(ctx)
			res.Response(nil, coreerror.New(coreerror.BadRequest, http.StatusBadRequest, "unsupported grant_type"), false)
			ctx.Abort()
			return
		}
		ctx.Set(GrantTypeKey, gt)
		ctx.Next()
	}
}

func jsonGrantType(ctx *gin.Context) string {
	contentType, _, err := mime.ParseMediaType(ctx.GetHeader("Content-Type"))
	if err != nil || contentType != "application/json" {
		return ""
	}
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxGrantTypeBodyBytes)
	body, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		return ""
	}
	ctx.Request.Body = io.NopCloser(bytes.NewReader(body))
	var tmp struct {
		GrantType string `json:"grant_type"`
	}
	if json.Unmarshal(body, &tmp) != nil {
		return ""
	}
	return tmp.GrantType
}
