package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func runRequestID(t *testing.T, inbound string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if inbound != "" {
		c.Request.Header.Set(RequestIDHeader, inbound)
	}
	RequestID()(c)
	return c, w
}

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	c, w := runRequestID(t, "")
	id := c.GetString(RequestIDKey)
	if id == "" {
		t.Fatal("expected a generated request id")
	}
	if w.Header().Get(RequestIDHeader) != id {
		t.Errorf("response header = %q, want %q", w.Header().Get(RequestIDHeader), id)
	}
}

func TestRequestID_HonorsInbound(t *testing.T) {
	c, w := runRequestID(t, "trace-abc-123")
	if got := c.GetString(RequestIDKey); got != "trace-abc-123" {
		t.Errorf("request id = %q, want inbound value", got)
	}
	if w.Header().Get(RequestIDHeader) != "trace-abc-123" {
		t.Errorf("response header = %q, want inbound value", w.Header().Get(RequestIDHeader))
	}
}

func TestRequestID_RejectsOversizedInbound(t *testing.T) {
	huge := strings.Repeat("x", maxInboundRequestID+1)
	c, _ := runRequestID(t, huge)
	if got := c.GetString(RequestIDKey); got == huge || got == "" {
		t.Errorf("oversized inbound id should be replaced, got %q", got)
	}
}
