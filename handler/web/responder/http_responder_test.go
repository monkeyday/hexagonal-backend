package responder

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	coreerror "sc/core/error"
	coreweb "sc/core/web"
	"testing"

	"github.com/gin-gonic/gin"
)

// ── test error types ──────────────────────────────────────────────────────────

type httpErr struct {
	status  int
	code    coreerror.ErrCode
	message string
}

func (e *httpErr) Error() string           { return e.message }
func (e *httpErr) Code() coreerror.ErrCode { return e.code }
func (e *httpErr) Data() any               { return nil }
func (e *httpErr) HTTPStatus() int         { return e.status }

type coreErr struct {
	code    coreerror.ErrCode
	message string
}

func (e *coreErr) Error() string           { return e.message }
func (e *coreErr) Code() coreerror.ErrCode { return e.code }
func (e *coreErr) Data() any               { return nil }

// ── helpers ───────────────────────────────────────────────────────────────────

func callResponder(fn func(r *HTTPResponder)) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	fn(NewHTTPResponder(c))
	return w
}

func decodeResponse(t *testing.T, body []byte) HTTPResponse {
	t.Helper()
	var resp HTTPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp
}

func setCookieSecure(c *gin.Context, enabled bool) {
	c.Set(coreweb.CookieSecureKey, enabled)
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestResponse_Success(t *testing.T) {
	w := callResponder(func(r *HTTPResponder) {
		r.Response(gin.H{"key": "value"}, nil, false)
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := decodeResponse(t, w.Body.Bytes())
	if resp.Msg != "" {
		t.Errorf("msg should be empty on responseJSON, got %q", resp.Msg)
	}
	if resp.ErrCode != 0 {
		t.Errorf("err_code should be 0 on responseJSON, got %d", resp.ErrCode)
	}
}

func TestResponse_NilData(t *testing.T) {
	w := callResponder(func(r *HTTPResponder) {
		r.Response(nil, nil, false)
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestResponse_HTTPError(t *testing.T) {
	tests := []struct {
		name       string
		err        *httpErr
		wantStatus int
		wantCode   coreerror.ErrCode
		wantMsg    string
	}{
		{
			name:       "401 HTTPError",
			err:        &httpErr{status: http.StatusUnauthorized, code: 10002, message: "invalid token"},
			wantStatus: http.StatusUnauthorized,
			wantCode:   10002,
			wantMsg:    "invalid token",
		},
		{
			name:       "400 HTTPError",
			err:        &httpErr{status: http.StatusBadRequest, code: 10001, message: "bad request"},
			wantStatus: http.StatusBadRequest,
			wantCode:   10001,
			wantMsg:    "bad request",
		},
		{
			name:       "409 HTTPError",
			err:        &httpErr{status: http.StatusConflict, code: 10016, message: "email duplicated"},
			wantStatus: http.StatusConflict,
			wantCode:   10016,
			wantMsg:    "email duplicated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := callResponder(func(r *HTTPResponder) { r.Response(nil, tc.err, false) })
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			resp := decodeResponse(t, w.Body.Bytes())
			if resp.ErrCode != tc.wantCode {
				t.Errorf("err_code = %d, want %d", resp.ErrCode, tc.wantCode)
			}
			if resp.Msg != tc.wantMsg {
				t.Errorf("msg = %q, want %q", resp.Msg, tc.wantMsg)
			}
		})
	}
}

func TestResponse_CoreError(t *testing.T) {
	err := &coreErr{code: 10004, message: "sign token failed"}
	w := callResponder(func(r *HTTPResponder) { r.Response(nil, err, false) })

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	resp := decodeResponse(t, w.Body.Bytes())
	if resp.ErrCode != 10004 {
		t.Errorf("err_code = %d, want 10004", resp.ErrCode)
	}
}

func TestResponse_PlainError(t *testing.T) {
	w := callResponder(func(r *HTTPResponder) {
		r.Response(nil, errors.New("something unexpected"), false)
	})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	resp := decodeResponse(t, w.Body.Bytes())
	if resp.ErrCode != 90000 {
		t.Errorf("err_code = %d, want 90000", resp.ErrCode)
	}
	if resp.Msg != "internal server error" {
		t.Errorf("msg = %q, want %q", resp.Msg, "internal server error")
	}
}

func TestResponse_HTTPErrorTakesPriorityOverCoreError(t *testing.T) {
	err := &httpErr{status: http.StatusForbidden, code: 10099, message: "forbidden"}
	var _ coreerror.Error = err // compile-time check

	w := callResponder(func(r *HTTPResponder) { r.Response(nil, err, false) })
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (HTTPError must take priority)", w.Code)
	}
}

type cookieData struct {
	name  string
	value string
}

func (c *cookieData) Cookies() []Cookie {
	return []Cookie{{Name: c.name, Value: c.value}}
}

func TestResponse_SetsCookieFromCookieResult(t *testing.T) {
	tests := []struct {
		name        string
		data        CookieResult
		wantCookie  string
		wantPresent bool
	}{
		{
			name:        "sets cookie when CookieResult has value",
			data:        &cookieData{name: "refresh_token", value: "tok123"},
			wantCookie:  "tok123",
			wantPresent: true,
		},
		{
			name:        "no cookie when data does not implement CookieResult",
			data:        nil,
			wantPresent: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			r := NewHTTPResponder(c)

			if tc.data != nil {
				r.Response(tc.data, nil, false)
			} else {
				r.Response(gin.H{"key": "val"}, nil, false)
			}

			cookies := w.Result().Cookies()
			found := false
			for _, ck := range cookies {
				if ck.Name == "refresh_token" {
					found = true
					if ck.Value != tc.wantCookie {
						t.Errorf("cookie value = %q, want %q", ck.Value, tc.wantCookie)
					}
					if !ck.HttpOnly {
						t.Error("cookie should be HttpOnly")
					}
				}
			}
			if found != tc.wantPresent {
				t.Errorf("cookie present = %v, want %v", found, tc.wantPresent)
			}
		})
	}
}

type redirectData struct {
	url string
}

func (r *redirectData) URL() string { return r.url }

func TestResponse_RedirectResult(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		wantStatus int
	}{
		{"GET redirect uses 302", http.MethodGet, http.StatusFound},
		{"POST redirect uses 303", http.MethodPost, http.StatusSeeOther},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Handle(tc.method, "/", func(c *gin.Context) {
				NewHTTPResponder(c).Response(&redirectData{url: "http://localhost:3000/callback?code=abc"}, nil, false)
			})

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, "/", nil))

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if got := w.Header().Get("Location"); got != "http://localhost:3000/callback?code=abc" {
				t.Errorf("Location = %q, want callback URL", got)
			}
			assertNoStoreHeaders(t, w)
		})
	}
}

type htmlData struct {
	page string
	data map[string]any
}

func (h *htmlData) HTMLPage() string         { return h.page }
func (h *htmlData) HTMLData() map[string]any { return h.data }

type noStoreHTMLData struct {
	htmlData
}

func (h *noStoreHTMLData) NoStore() bool { return true }

func TestResponse_HTMLResult_DefaultsToCacheable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.SetHTMLTemplate(template.Must(
		template.New("sign_in.html").Parse(`<html>{{.csrf_token}}</html>`),
	))
	router.GET("/", func(c *gin.Context) {
		NewHTTPResponder(c).Response(
			&htmlData{page: "sign_in", data: map[string]any{"csrf_token": "tok-abc"}},
			nil, false,
		)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if body := w.Body.String(); body != "<html>tok-abc</html>" {
		t.Errorf("body = %q, want <html>tok-abc</html>", body)
	}
	assertNoNoStoreHeaders(t, w)
}

func TestResponse_HTMLResult_NoStoreOptIn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.SetHTMLTemplate(template.Must(
		template.New("sign_in.html").Parse(`<html>{{.csrf_token}}</html>`),
	))
	router.GET("/", func(c *gin.Context) {
		NewHTTPResponder(c).Response(
			&noStoreHTMLData{htmlData{page: "sign_in", data: map[string]any{"csrf_token": "tok-abc"}}},
			nil, false,
		)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if body := w.Body.String(); body != "<html>tok-abc</html>" {
		t.Errorf("body = %q, want <html>tok-abc</html>", body)
	}
	assertNoStoreHeaders(t, w)
}

func assertNoStoreHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	if got := w.Header().Get("Expires"); got != "0" {
		t.Errorf("Expires = %q, want 0", got)
	}
}

func assertNoNoStoreHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, header := range []string{"Cache-Control", "Pragma", "Expires"} {
		if got := w.Header().Get(header); got != "" {
			t.Errorf("%s = %q, want empty", header, got)
		}
	}
}

func TestResponse_CookieSecure(t *testing.T) {
	tests := []struct {
		name         string
		configSecure bool
		spoofHeader  string
		wantSecure   bool
	}{
		{"config true sets Secure", true, "", true},
		{"config false does not set Secure", false, "", false},
		{"spoofed X-Forwarded-Proto: https ignored without config", false, "https", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.spoofHeader != "" {
				c.Request.Header.Set("X-Forwarded-Proto", tc.spoofHeader)
			}
			setCookieSecure(c, tc.configSecure)
			NewHTTPResponder(c).Response(&cookieData{name: "refresh_token", value: "tok"}, nil, false)

			for _, ck := range w.Result().Cookies() {
				if ck.Name == "refresh_token" {
					if ck.Secure != tc.wantSecure {
						t.Errorf("Secure = %v, want %v", ck.Secure, tc.wantSecure)
					}
					return
				}
			}
			t.Error("refresh_token cookie not found")
		})
	}
}

func TestResponse_HTMLErrorStatus(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "HTTPError propagates its status to HTML response",
			err:        &httpErr{status: http.StatusBadRequest, code: 10001, message: "bad request"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "plain error uses 500",
			err:        &coreErr{code: 10004, message: "something broke"},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.SetHTMLTemplate(template.Must(
				template.New("error.html").Parse(`<html>{{.message}}</html>`),
			))
			router.GET("/", func(c *gin.Context) {
				NewHTTPResponder(c).Response(nil, tc.err, true)
			})

			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
		})
	}
}

func TestResponse_NoCookieOnError(t *testing.T) {
	w := callResponder(func(r *HTTPResponder) {
		r.Response(&cookieData{name: "refresh_token", value: "tok"}, &httpErr{status: http.StatusUnauthorized, code: 401, message: "unauthorized"}, false)
	})
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "refresh_token" {
			t.Error("should not set cookie on error response")
		}
	}
}
