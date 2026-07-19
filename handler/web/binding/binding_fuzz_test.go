package binding

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// FuzzBind drives the full bind pipeline (uri/query/header/body + the
// reflect-based ctx/cookie/file/normalize pass) with untrusted request inputs.
// It must never panic, and normalizeURI — which feeds redirect_uri validation —
// must be idempotent for whatever value lands in the field.
func FuzzBind(f *testing.F) {
	type target struct {
		Name        string `form:"name" json:"name"`
		Age         int    `form:"age" json:"age"`
		Token       string `header:"X-Token"`
		Refresh     string `form:"refresh_token" cookie:"refresh_token"`
		UserID      string `ctx:"user_id"`
		RedirectURI string `form:"redirect_uri" json:"redirect_uri" normalize:"uri"`
	}

	seeds := []struct {
		method, target, body, contentType, header, cookie string
	}{
		{http.MethodGet, "/?name=alice&age=30", "", "", "", ""},
		{http.MethodPost, "/", `{"name":"bob","age":25}`, "application/json", "", ""},
		{http.MethodPost, "/", "refresh_token=body&redirect_uri=HTTPS://app.example.com/cb", "application/x-www-form-urlencoded", "", "stale-cookie"},
		{http.MethodGet, "/?redirect_uri=HTTPS://app.example.com/callback#frag", "", "", "secret", ""},
		{http.MethodPost, "/", "", "application/json", "", ""},
	}
	for _, s := range seeds {
		f.Add(s.method, s.target, s.body, s.contentType, s.header, s.cookie)
	}

	f.Fuzz(func(t *testing.T, method, tgt, body, contentType, header, cookie string) {
		// http.NewRequest validates the method token and URL; the binding layer
		// only ever sees requests Gin already accepted, so skip inputs that
		// could never reach it rather than treat them as bind failures.
		req, err := http.NewRequest(method, tgt, strings.NewReader(body))
		if err != nil {
			return
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if header != "" {
			req.Header.Set("X-Token", header)
		}
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: cookie})
		}

		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = req
		c.Set("user_id", "u-1")

		var out target
		_ = Bind(c, &out) // must never panic

		once := normalizeURI(out.RedirectURI)
		if twice := normalizeURI(once); once != twice {
			t.Fatalf("normalizeURI not idempotent: %q -> %q -> %q", out.RedirectURI, once, twice)
		}
	})
}
