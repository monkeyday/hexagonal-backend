package middleware

import (
	"context"
	"strings"

	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"sc/handler/web/responder"

	"github.com/gin-gonic/gin"
)

type TokenParser interface {
	ParseJWT(tokenString string) (*corejwt.Claims, error)
}

// RevocationChecker reports whether an access token (identified by its jti)
// has been revoked. The middleware depends on this narrow port instead of the
// auth module's cache-key convention, keeping the delivery layer free of
// module-specific knowledge.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

const (
	authorizationHeader   = "Authorization"
	wwwAuthenticate       = "WWW-Authenticate"
	wwwAuthenticateBearer = "Bearer"
	TokenKey              = "access_token"
	IssuerKey             = "issuer"
	UserIdKey             = "user_id"
	BasicClientIDKey      = "basic_client_id"
	BasicClientSecretKey  = "basic_client_secret"
)

// ExtractClientCredentials exposes HTTP Basic credentials (client_secret_basic)
// to commands via ctx-bound fields. Verification happens in the application
// layer; this only adapts the transport.
func ExtractClientCredentials() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if id, secret, ok := ctx.Request.BasicAuth(); ok {
			ctx.Set(BasicClientIDKey, id)
			ctx.Set(BasicClientSecretKey, secret)
		}
		ctx.Next()
	}
}

// ExtractAccessToken Use this on routes where a token is useful but not required (e.g., logout).
func ExtractAccessToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if token, ok := extractBearerToken(ctx.GetHeader(authorizationHeader)); ok {
			ctx.Set(TokenKey, token)
		}
		ctx.Next()
	}
}

func Authenticate(svc TokenParser, rev RevocationChecker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		claims, token, ok := verifyBearer(ctx, svc, rev)
		if !ok {
			ctx.Header(wwwAuthenticate, wwwAuthenticateBearer)
			res := responder.NewHTTPResponder(ctx)
			res.Response(nil, coreerror.New(coreerror.Unauthorized, 401, "invalid token"), false)
			ctx.Abort()
			return
		}
		setBearerIdentity(ctx, claims, token)
		ctx.Next()
	}
}

// AuthenticateOptional attaches bearer identity when a valid token is
// presented but never rejects the request. For endpoints that accept either
// a bearer token or client credentials (revoke/introspect per RFC 7009/7662);
// the use case enforces that at least one of them authenticated.
func AuthenticateOptional(svc TokenParser, rev RevocationChecker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if claims, token, ok := verifyBearer(ctx, svc, rev); ok {
			setBearerIdentity(ctx, claims, token)
		}
		ctx.Next()
	}
}

// verifyBearer validates the Authorization bearer token: signature/claims via
// the parser, a mandatory jti, and a fail-closed revocation-blacklist check.
func verifyBearer(ctx *gin.Context, svc TokenParser, rev RevocationChecker) (*corejwt.Claims, string, bool) {
	accessToken, ok := extractBearerToken(ctx.GetHeader(authorizationHeader))
	if !ok {
		return nil, "", false
	}
	claims, err := svc.ParseJWT(accessToken)
	if err != nil || claims == nil {
		return nil, "", false
	}
	// A token without jti cannot be checked against the revocation
	// blacklist, so it must be rejected, not waved through.
	if claims.ID == "" {
		return nil, "", false
	}
	if rev != nil {
		revoked, err := rev.IsRevoked(ctx.Request.Context(), claims.ID)
		if err != nil || revoked {
			return nil, "", false
		}
	}
	return claims, accessToken, true
}

func setBearerIdentity(ctx *gin.Context, claims *corejwt.Claims, token string) {
	ctx.Set(TokenKey, token)
	ctx.Set(IssuerKey, claims.Issuer)
	ctx.Set(UserIdKey, claims.Subject)
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
