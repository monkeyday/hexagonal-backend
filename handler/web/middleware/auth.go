package middleware

import (
	"fmt"
	"strings"

	corecache "sc/core/cache"
	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"sc/handler/web/responder"
	"sc/modules/auth/application/define"

	"github.com/gin-gonic/gin"
)

type TokenParser interface {
	ParseJWT(tokenString string) (*corejwt.Claims, error)
}

const (
	authorizationHeader   = "Authorization"
	wwwAuthenticate       = "WWW-Authenticate"
	wwwAuthenticateBearer = "Bearer"
	TokenKey              = "access_token"
	IssuerKey             = "issuer"
	UserIdKey             = "user_id"
)

// ExtractAccessToken Use this on routes where a token is useful but not required (e.g., logout).
func ExtractAccessToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if token, ok := extractBearerToken(ctx.GetHeader(authorizationHeader)); ok {
			ctx.Set(TokenKey, token)
		}
		ctx.Next()
	}
}

func Authenticate(svc TokenParser, c corecache.ReadErrorCache) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		res := responder.NewHTTPResponder(ctx)

		accessToken, ok := extractBearerToken(ctx.GetHeader(authorizationHeader))
		if !ok {
			ctx.Header(wwwAuthenticate, wwwAuthenticateBearer)
			res.Response(nil, coreerror.New(coreerror.Unauthorized, 401, "token not found"), false)
			ctx.Abort()
			return
		}

		claims, err := svc.ParseJWT(accessToken)
		if err != nil || claims == nil {
			ctx.Header(wwwAuthenticate, wwwAuthenticateBearer)
			res.Response(nil, coreerror.New(coreerror.Unauthorized, 401, "invalid token"), false)
			ctx.Abort()
			return
		}

		if claims.ID != "" && c != nil {
			revoked, err := c.GetErr(ctx.Request.Context(), fmt.Sprintf(define.BlacklistCacheKey, claims.ID), nil)
			if err != nil || revoked {
				ctx.Header(wwwAuthenticate, wwwAuthenticateBearer)
				res.Response(nil, coreerror.New(coreerror.Unauthorized, 401, "invalid token"), false)
				ctx.Abort()
				return
			}
		}

		ctx.Set(TokenKey, accessToken)
		ctx.Set(IssuerKey, claims.Issuer)
		ctx.Set(UserIdKey, claims.Subject)
		ctx.Next()
	}
}

// extractBearerToken extracts the token from an Authorization header.
// The Bearer scheme is case-insensitive per RFC 7235.
func extractBearerToken(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}
