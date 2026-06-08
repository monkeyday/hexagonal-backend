package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newCORSRouter(origins []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Cors(origins))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.OPTIONS("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	return r
}

func TestCors(t *testing.T) {
	t.Run("allowed origin receives ACAO header", func(t *testing.T) {
		r := newCORSRouter([]string{"https://app.example.com"})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Errorf("ACAO = %q, want https://app.example.com", got)
		}
	})

	t.Run("disallowed origin does not receive ACAO header", func(t *testing.T) {
		r := newCORSRouter([]string{"https://app.example.com"})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got == "https://evil.example.com" {
			t.Error("disallowed origin must not appear in ACAO header")
		}
	})

	t.Run("wildcard origin allows any request origin", func(t *testing.T) {
		r := newCORSRouter([]string{"*"})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://any.domain.io")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Origin"); got == "" {
			t.Error("wildcard config should set ACAO header")
		}
	})

	t.Run("preflight OPTIONS returns 204 with allow headers", func(t *testing.T) {
		r := newCORSRouter([]string{"https://app.example.com"})
		req := httptest.NewRequest(http.MethodOptions, "/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Authorization")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("preflight status = %d, want 204", w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Headers"); got == "" {
			t.Error("preflight must return Access-Control-Allow-Headers")
		}
	})

	t.Run("Access-Control-Allow-Credentials is true", func(t *testing.T) {
		r := newCORSRouter([]string{"https://app.example.com"})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("ACAC = %q, want true", got)
		}
	})
}
