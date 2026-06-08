package adapter

import (
	corecache "sc/core/cache"
	webHandler "sc/handler/web"
	"sc/handler/web/middleware"
	"sc/handler/web/responder"
	"sc/modules/auth/application/command"
	"sc/modules/auth/application/query"
	"sc/modules/auth/port"

	"github.com/gin-gonic/gin"
)

const (
	grantTypeRefreshToken = "refresh_token"
	grantTypeAuthCode     = "authorization_code"
	grantTypePassword     = "password"
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
	kc.GET("/certs", webHandler.Handle[query.GetJWKSQuery](ro.module))

	// password grant is intentionally — restricted to internal/trusted clients,
	// not exposed to public or browser-based consumers.
	r.POST("/token",
		middleware.GrantType([]string{grantTypeRefreshToken, grantTypeAuthCode, grantTypePassword}),
		webHandler.HandleIf[command.RefreshTokenCommand](ro.module, grantTypeIs(grantTypeRefreshToken)),
		webHandler.HandleIf[command.ExchangeCodeCommand](ro.module, grantTypeIs(grantTypeAuthCode)),
		webHandler.HandleIf[query.GetTokenQuery](ro.module, grantTypeIs(grantTypePassword)),
	)
	kc.POST("/token",
		middleware.GrantType([]string{grantTypeRefreshToken, grantTypeAuthCode, grantTypePassword}),
		webHandler.HandleIf[command.RefreshTokenCommand](ro.module, grantTypeIs(grantTypeRefreshToken)),
		webHandler.HandleIf[command.ExchangeCodeCommand](ro.module, grantTypeIs(grantTypeAuthCode)),
		webHandler.HandleIf[query.GetTokenQuery](ro.module, grantTypeIs(grantTypePassword)),
	)
	r.POST("/sign-up", webHandler.Handle[command.CreateUserCommand](ro.module))
	r.POST("/sign-in", webHandler.Handle[command.CreateAuthCodeCommand](ro.module))
	r.POST("/forgot-password", webHandler.Handle[command.ForgotPasswordCommand](ro.module))
	r.POST("/reset-password", webHandler.Handle[command.ResetPasswordCommand](ro.module))
	r.GET("/.well-known/openid-configuration", webHandler.Handle[query.GetDiscoveryQuery](ro.module))
	r.GET("/.well-known/jwks.json", webHandler.Handle[query.GetJWKSQuery](ro.module))
}

func (ro *Router) registerOIDCRoutes(r *gin.Engine) {
	auth := middleware.Authenticate(ro.jwtSvc, ro.cache)
	r.GET("/userinfo", auth, webHandler.Handle[query.GetProfileQuery](ro.module))
	r.GET("/protocol/openid-connect/userinfo", auth, webHandler.Handle[query.GetProfileQuery](ro.module))

	oidc := r.Group("/oidc")
	oidc.GET("/logout", middleware.ExtractAccessToken(), webHandler.Handle[command.LogoutCommand](ro.module))
	oidc.Use(auth)
	oidc.GET("/me", webHandler.Handle[query.GetProfileQuery](ro.module))
	oidc.POST("/revoke", webHandler.Handle[command.RevokeTokenCommand](ro.module))
	oidc.POST("/introspect", webHandler.Handle[query.IntrospectTokenQuery](ro.module))
}

func (ro *Router) registerV3Routes(r *gin.Engine) {
	apiV3 := r.Group("/api/v3")
	apiV3.Use(middleware.Authenticate(ro.jwtSvc, ro.cache))
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
