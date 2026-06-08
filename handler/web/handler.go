package webHandler

import (
	"context"
	"expvar"
	"html/template"
	"sc/assets"
	corecache "sc/core/cache"
	"sc/core/usecase"
	coreweb "sc/core/web"
	"sc/handler/web/binding"
	"sc/handler/web/middleware"
	"sc/handler/web/responder"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type HTTPErrorMapper interface {
	MapHTTPError(err error) error
}

type HTTPUseCaseModule interface {
	usecase.Dispatcher
	HTTPErrorMapper
}

type HTTPModule interface {
	HTTPUseCaseModule
	RegisterRoutes(r *gin.Engine)
}

var (
	once  sync.Once
	e     *Engine
	Start = instance().start // returns a non-nil error only on startup failure; SIGINT/SIGTERM return nil
)

type Engine struct {
	*gin.Engine
}

func instance() *Engine {
	once.Do(func() {
		e = &Engine{gin.Default()}
	})
	return e
}

type Args struct {
	Server  coreweb.Config
	Cleanup func(context.Context)
	Cache   corecache.Cache
}

func (e *Engine) start(modules []HTTPModule, args Args) error {
	as := &assets.EmbedAssets{}
	tmpl := template.Must(template.ParseFS(as.GetTemplates(), "*.html"))
	e.SetHTMLTemplate(tmpl)
	e.setMiddlewares(args)
	e.wire(modules)
	return e.run(args.Server.Port, args.Cleanup)
}

func (e *Engine) setMiddlewares(args Args) {
	e.Use(middleware.Logger())
	e.Use(middleware.Cors(args.Server.CorsOrigins))
	e.Use(middleware.CookieSecure(args.Server.CookieSecure))
	e.Use(middleware.DistributedRateLimit(args.Cache, 1000, time.Minute))
	e.GET("/debug/vars", gin.WrapH(expvar.Handler()))
}

func (e *Engine) wire(modules []HTTPModule) {
	for _, m := range modules {
		m.RegisterRoutes(e.Engine)
	}
}

func handle[T any](m HTTPUseCaseModule, isHTML bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		cmd := new(T)
		res := responder.NewHTTPResponder(ctx)
		if err := binding.Bind(ctx, cmd); err != nil {
			res.Response(nil, err, isHTML)
			return
		}
		result, err := m.Dispatch(ctx.Request.Context(), cmd)
		res.Response(result, m.MapHTTPError(err), isHTML)
	}
}

func Handle[T any](m HTTPUseCaseModule) gin.HandlerFunc {
	return handle[T](m, false)
}

// HandleHTML is like Handle but renders error.html on failure instead of a JSON error body.
// Use for browser-facing routes where the client cannot interpret a JSON error response.
func HandleHTML[T any](m HTTPUseCaseModule) gin.HandlerFunc {
	return handle[T](m, true)
}

func HandleIf[T any](m HTTPUseCaseModule, when func(*gin.Context) bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if !when(ctx) {
			ctx.Next()
			return
		}
		cmd := new(T)
		res := responder.NewHTTPResponder(ctx)
		if err := binding.Bind(ctx, cmd); err != nil {
			res.Response(nil, m.MapHTTPError(err), false)
			ctx.Abort()
			return
		}
		result, err := m.Dispatch(ctx.Request.Context(), cmd)
		res.Response(result, m.MapHTTPError(err), false)
		ctx.Abort()
	}
}
