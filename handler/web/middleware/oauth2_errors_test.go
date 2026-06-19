package middleware

import (
	"net/http"
	"net/http/httptest"
	"sc/core/web"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestOAuth2Errors_SetsFormatFlag(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/token", nil)

	var seen bool
	OAuth2Errors()(c)
	if v, ok := c.Get(web.OAuth2ErrorFormatKey); ok {
		seen, _ = v.(bool)
	}
	if !seen {
		t.Error("OAuth2Errors must set the OAuth2 error-format flag")
	}
}
