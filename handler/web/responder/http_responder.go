package responder

import (
	"net/http"
	coreerror "sc/core/error"
	"sc/core/web"

	"github.com/gin-gonic/gin"
)

type HTTPResponse struct {
	Data    any               `json:"data,omitempty"`
	Msg     string            `json:"msg,omitempty"`
	ErrCode coreerror.ErrCode `json:"err_code,omitempty"`
}

// Cookie is an alias so existing code using responder.Cookie continues to compile.
type Cookie = web.Cookie

type CookieResult interface {
	Cookies() []web.Cookie
}

type RedirectResult interface {
	URL() string
}

type HTMLResult interface {
	HTMLPage() string
	HTMLData() map[string]any
}

type NoStoreResult interface {
	NoStore() bool
}

const templateExt = ".html"

type HTTPResponder struct {
	c *gin.Context
}

func NewHTTPResponder(c *gin.Context) *HTTPResponder {
	return &HTTPResponder{c: c}
}

func (r *HTTPResponder) Response(data any, err error, isHTML bool) {
	if err != nil {
		r.fail(err, isHTML)
		return
	}
	if c, ok := data.(CookieResult); ok {
		r.setCookies(c.Cookies())
	}

	if u, ok := data.(RedirectResult); ok && u.URL() != "" {
		r.noStore()
		r.redirect(r.redirectStatus(), u.URL())
		return
	}

	if h, ok := data.(HTMLResult); ok {
		if shouldNoStore(data) {
			r.noStore()
		}
		r.c.HTML(http.StatusOK, h.HTMLPage()+templateExt, h.HTMLData())
		return
	}

	r.responseJSON(data)
}

func (r *HTTPResponder) ResponseWithHTML(page, title string) {
	r.c.HTML(http.StatusOK, page+templateExt, gin.H{"title": title})
}

func shouldNoStore(data any) bool {
	n, ok := data.(NoStoreResult)
	return ok && n.NoStore()
}

func (r *HTTPResponder) noStore() {
	r.c.Header("Cache-Control", "no-store")
	r.c.Header("Pragma", "no-cache")
	r.c.Header("Expires", "0")
}

func (r *HTTPResponder) redirectStatus() int {
	if r.c.Request != nil && r.c.Request.Method == http.MethodPost {
		return http.StatusSeeOther
	}
	return http.StatusFound
}

func (r *HTTPResponder) redirect(status int, url string) {
	r.c.Header("Location", url)
	r.c.Header("Content-Length", "0")
	r.c.Status(status)
}

func (r *HTTPResponder) setCookies(cookies []Cookie) {
	secure, _ := r.c.Get(web.CookieSecureKey)
	cookieSecure, _ := secure.(bool)
	for _, c := range cookies {
		sameSite := http.SameSiteStrictMode
		if c.SameSite != nil {
			sameSite = *c.SameSite
		}

		r.c.SetSameSite(sameSite)
		r.c.SetCookie(c.Name, c.Value, c.MaxAge, "/", "", cookieSecure, true)
	}
}

func (r *HTTPResponder) responseJSON(data any) {
	r.c.JSON(http.StatusOK, data)
}

type HTTPError interface {
	coreerror.Error
	HTTPStatus() int
}

func (r *HTTPResponder) fail(err error, isHTML bool) {
	if isHTML {
		status := http.StatusInternalServerError
		if e, ok := err.(HTTPError); ok && e.HTTPStatus() != 0 {
			status = e.HTTPStatus()
		}
		r.c.HTML(status, "error"+templateExt, gin.H{
			"title":   "Something went wrong",
			"message": err.Error(),
		})
		return
	}
	if r.oauth2Format() {
		r.failOAuth2(err)
		return
	}
	if e, ok := err.(HTTPError); ok && e.HTTPStatus() != 0 {
		r.c.JSON(e.HTTPStatus(), &HTTPResponse{
			Msg:     e.Error(),
			ErrCode: e.Code(),
		})
		return
	}
	if e, ok := err.(coreerror.Error); ok {
		r.c.JSON(http.StatusInternalServerError, &HTTPResponse{
			Msg:     e.Error(),
			ErrCode: e.Code(),
		})
		return
	}
	r.c.JSON(http.StatusInternalServerError, &HTTPResponse{
		Msg:     "internal server error",
		ErrCode: 90000,
	})
}

// oauth2ErrorBody is the RFC 6749 §5.2 error response shape.
type oauth2ErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (r *HTTPResponder) oauth2Format() bool {
	v, ok := r.c.Get(web.OAuth2ErrorFormatKey)
	b, _ := v.(bool)
	return ok && b
}

// failOAuth2 renders an RFC 6749 §5.2 error body. The error code comes from the
// error when it carries one (web.OAuth2Error), defaulting to invalid_request.
// An invalid_client failure additionally gets a WWW-Authenticate challenge
// (RFC 6749 §5.2).
func (r *HTTPResponder) failOAuth2(err error) {
	status := http.StatusBadRequest
	if e, ok := err.(interface{ HTTPStatus() int }); ok && e.HTTPStatus() != 0 {
		status = e.HTTPStatus()
	}
	code := web.OAuth2InvalidRequest
	desc := err.Error()
	if e, ok := err.(web.OAuth2Error); ok {
		if c := e.OAuth2Code(); c != "" {
			code = c
		}
		desc = e.OAuth2Description()
	}
	if code == web.OAuth2InvalidClient && status == http.StatusUnauthorized {
		r.c.Header("WWW-Authenticate", `Basic realm="oauth2"`)
	}
	r.c.JSON(status, oauth2ErrorBody{Error: code, ErrorDescription: desc})
}
