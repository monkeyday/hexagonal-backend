package adapter

import (
	corecache "sc/core/cache"
	webHandler "sc/handler/web"
	"sc/handler/web/middleware"
	"sc/handler/web/responder"
	"sc/modules/auth/application/command"
	"sc/modules/auth/application/query"
	"sc/modules/auth/port"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	grantTypeRefreshToken = "refresh_token"
	grantTypeAuthCode     = "authorization_code"
	grantTypePassword     = "password"

	// discoveryCacheTTL applies to the public, non-sensitive metadata
	// endpoints (discovery, JWKS); everything else is no-store.
	discoveryCacheTTL = 5 * time.Minute
)

type Router struct {
	module webHandler.HTTPUseCaseModule
	jwtSvc port.TokenParser
	cache  corecache.Cache
}

func NewRouter(m webHandler.HTTPUseCaseModule, jwtSvc port.TokenParser, cache corecache.Cache) *Router {
	return &Router{module: m, jwtSvc: jwtSvc, cache: cache}
}

func (ro *Router) RegisterRoutes(r *gin.Engine) {
	ro.registerPublicRoutes(r)
	ro.registerOIDCRoutes(r)
	ro.registerV3Routes(r)
}

func (ro *Router) registerPublicRoutes(r *gin.Engine) {
	r.GET("/sign-in", webHandler.HandleHTML[query.GetSignInQuery](ro.module))
	r.GET("/sign-up", signUp())
	r.GET("/authorize", webHandler.Handle[query.GetAuthorizeQuery](ro.module))
	kc := r.Group("/protocol/openid-connect")
	kc.GET("/auth", webHandler.Handle[query.GetAuthorizeQuery](ro.module))
	kc.GET("/certs", middleware.CachePublic(discoveryCacheTTL), webHandler.Handle[query.GetJWKSQuery](ro.module))

	// password grant is intentionally — restricted to internal/trusted clients,
	// not exposed to public or browser-based consumers.
	r.POST("/token", ro.tokenHandlers()...)
	kc.POST("/token", ro.tokenHandlers()...)
	r.POST("/sign-up", webHandler.Handle[command.CreateUserCommand](ro.module))
	r.POST("/sign-in", webHandler.Handle[command.CreateAuthCodeCommand](ro.module))
	r.POST("/forgot-password", webHandler.Handle[command.ForgotPasswordCommand](ro.module))
	r.POST("/reset-password", webHandler.Handle[command.ResetPasswordCommand](ro.module))
	r.GET("/.well-known/openid-configuration", middleware.CachePublic(discoveryCacheTTL), webHandler.Handle[query.GetDiscoveryQuery](ro.module))
	r.GET("/.well-known/jwks.json", middleware.CachePublic(discoveryCacheTTL), webHandler.Handle[query.GetJWKSQuery](ro.module))
}

func (ro *Router) tokenHandlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		middleware.GrantType([]string{grantTypeRefreshToken, grantTypeAuthCode, grantTypePassword}),
		middleware.ExtractClientCredentials(),
		webHandler.HandleIf[command.RefreshTokenCommand](ro.module, grantTypeIs(grantTypeRefreshToken)),
		webHandler.HandleIf[command.ExchangeCodeCommand](ro.module, grantTypeIs(grantTypeAuthCode)),
		webHandler.HandleIf[query.GetTokenQuery](ro.module, grantTypeIs(grantTypePassword)),
	}
}

func (ro *Router) registerOIDCRoutes(r *gin.Engine) {
	rev := newRevocationChecker(ro.cache)
	auth := middleware.Authenticate(ro.jwtSvc, rev)
	r.GET("/userinfo", auth, webHandler.Handle[query.GetProfileQuery](ro.module))
	r.GET("/protocol/openid-connect/userinfo", auth, webHandler.Handle[query.GetProfileQuery](ro.module))

	oidc := r.Group("/oidc")
	oidc.GET("/logout", middleware.ExtractAccessToken(), webHandler.Handle[command.LogoutCommand](ro.module))
	oidc.POST("/logout", middleware.ExtractAccessToken(), webHandler.Handle[command.LogoutCommand](ro.module))
	// revoke accepts bearer OR client credentials (RFC 7009); introspect
	// requires an authenticated confidential client (RFC 7662 §2.1) — a bearer
	// token alone would let any user introspect arbitrary presented tokens.
	optionalAuth := middleware.AuthenticateOptional(ro.jwtSvc, rev)
	oidc.POST("/revoke", optionalAuth, middleware.ExtractClientCredentials(), webHandler.Handle[command.RevokeTokenCommand](ro.module))
	oidc.POST("/introspect", middleware.ExtractClientCredentials(), webHandler.Handle[query.IntrospectTokenQuery](ro.module))
	oidc.Use(auth)
	oidc.GET("/me", webHandler.Handle[query.GetProfileQuery](ro.module))
}

func (ro *Router) registerV3Routes(r *gin.Engine) {
	apiV3 := r.Group("/api/v3")
	apiV3.Use(middleware.Authenticate(ro.jwtSvc, newRevocationChecker(ro.cache)))
	apiV3.POST("/update-profile", webHandler.Handle[command.UpdateProfileCommand](ro.module))
}

func signUp() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		res := responder.NewHTTPResponder(ctx)
		res.ResponseWithHTML("sign_up", "Create Account")
	}
}

func grantTypeIs(gt string) func(*gin.Context) bool {
	return func(ctx *gin.Context) bool {
		v, _ := ctx.Get(middleware.GrantTypeKey)
		return v == gt
	}
}
