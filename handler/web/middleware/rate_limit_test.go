package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sc/infrastructure/cache"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func newRateLimitRouter(limit int64, window time.Duration) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	c := cache.NewMemoryCache()
	router.GET("/", DistributedRateLimit(c, limit, window), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return router
}

func doRequest(r *gin.Engine, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestRateLimit(t *testing.T) {
	t.Run("requests within limit are allowed", func(t *testing.T) {
		r := newRateLimitRouter(3, time.Minute)
		for i := range 3 {
			if code := doRequest(r, "1.2.3.4"); code != http.StatusOK {
				t.Fatalf("request %d: status = %d, want 200", i+1, code)
			}
		}
	})

	t.Run("request exceeding limit is rejected with 429", func(t *testing.T) {
		r := newRateLimitRouter(2, time.Minute)
		doRequest(r, "2.3.4.5")
		doRequest(r, "2.3.4.5")
		if code := doRequest(r, "2.3.4.5"); code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", code)
		}
	})

	t.Run("different IPs have independent limits", func(t *testing.T) {
		r := newRateLimitRouter(1, time.Minute)
		// exhaust IP A
		doRequest(r, "10.0.0.1")
		if code := doRequest(r, "10.0.0.1"); code != http.StatusTooManyRequests {
			t.Fatalf("IP A second request: want 429, got %d", code)
		}
		// IP B still has its own full limit
		if code := doRequest(r, "10.0.0.2"); code != http.StatusOK {
			t.Fatalf("IP B first request: want 200, got %d", code)
		}
	})

	t.Run("limit=1 allows exactly one request", func(t *testing.T) {
		r := newRateLimitRouter(1, time.Minute)
		if code := doRequest(r, "5.5.5.5"); code != http.StatusOK {
			t.Fatalf("first request: want 200, got %d", code)
		}
		if code := doRequest(r, "5.5.5.5"); code != http.StatusTooManyRequests {
			t.Fatalf("second request: want 429, got %d", code)
		}
	})

	t.Run("empty RemoteAddr is rejected with 429", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.GET("/", DistributedRateLimit(cache.NewMemoryCache(), 1, time.Minute), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "" // clear the default set by httptest
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("empty RemoteAddr: status = %d, want 429", w.Code)
		}
	})

	for _, path := range []string{"/token", "/sign-in", "/protocol/openid-connect/token"} {
		path := path
		t.Run("cache error fails closed for "+path, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			r := gin.New()
			r.POST(path, DistributedRateLimit(errCache{}, 3, time.Minute), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.RemoteAddr = "9.9.9.9:1234"
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("%s: status = %d, want 429", path, w.Code)
			}
		})
	}

	t.Run("cache error fails open for non-sensitive endpoint", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.GET("/health", DistributedRateLimit(errCache{}, 3, time.Minute), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "9.9.9.10:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
	})
}

type errCache struct{}

func (errCache) Set(context.Context, string, any, *time.Duration) error { return nil }
func (errCache) Get(context.Context, string, any) bool                  { return false }
func (errCache) GetErr(context.Context, string, any) (bool, error)      { return false, nil }
func (errCache) GetAndDelete(context.Context, string, any) bool         { return false }
func (errCache) Delete(context.Context, string)                         {}
func (errCache) Incr(context.Context, string) (int64, error)            { return 0, errors.New("cache down") }
func (errCache) Expire(context.Context, string, time.Duration) error    { return nil }
