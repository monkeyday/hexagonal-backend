package responder

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	coreweb "sc/core/web"
	"testing"

	"github.com/gin-gonic/gin"
)

// oauth2Err implements web.OAuth2Error + HTTPStatus, mirroring what the module's
// HTTPError wrapper provides.
type oauth2Err struct {
	status int
	code   string
	desc   string
}

func (e *oauth2Err) Error() string             { return e.desc }
func (e *oauth2Err) HTTPStatus() int           { return e.status }
func (e *oauth2Err) OAuth2Code() string        { return e.code }
func (e *oauth2Err) OAuth2Description() string { return e.desc }

func callOAuth2Responder(flag bool, fn func(r *HTTPResponder)) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/token", nil)
	if flag {
		c.Set(coreweb.OAuth2ErrorFormatKey, true)
	}
	fn(NewHTTPResponder(c))
	return w
}

func decodeOAuth2(t *testing.T, body []byte) oauth2ErrorBody {
	t.Helper()
	var b oauth2ErrorBody
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return b
}

func TestFailOAuth2_RendersRFCBody(t *testing.T) {
	w := callOAuth2Responder(true, func(r *HTTPResponder) {
		r.Response(nil, &oauth2Err{status: http.StatusBadRequest, code: coreweb.OAuth2InvalidGrant, desc: "bad code"}, false)
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	body := decodeOAuth2(t, w.Body.Bytes())
	if body.Error != coreweb.OAuth2InvalidGrant {
		t.Errorf("error = %q, want %q", body.Error, coreweb.OAuth2InvalidGrant)
	}
	if body.ErrorDescription != "bad code" {
		t.Errorf("error_description = %q, want %q", body.ErrorDescription, "bad code")
	}
}

func TestFailOAuth2_InvalidClientGetsChallenge(t *testing.T) {
	w := callOAuth2Responder(true, func(r *HTTPResponder) {
		r.Response(nil, &oauth2Err{status: http.StatusUnauthorized, code: coreweb.OAuth2InvalidClient, desc: "client auth failed"}, false)
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("invalid_client 401 must carry a WWW-Authenticate challenge")
	}
	if body := decodeOAuth2(t, w.Body.Bytes()); body.Error != coreweb.OAuth2InvalidClient {
		t.Errorf("error = %q, want invalid_client", body.Error)
	}
}

func TestFailOAuth2_PlainErrorDefaultsToInvalidRequest(t *testing.T) {
	w := callOAuth2Responder(true, func(r *HTTPResponder) {
		r.Response(nil, errors.New("boom"), false)
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 default", w.Code)
	}
	if body := decodeOAuth2(t, w.Body.Bytes()); body.Error != coreweb.OAuth2InvalidRequest {
		t.Errorf("error = %q, want invalid_request", body.Error)
	}
}

func TestFail_NonOAuth2RouteKeepsDefaultShape(t *testing.T) {
	// Without the flag, an OAuth2-coded error must still render the default
	// {"msg","err_code"} shape so non-OAuth endpoints are unaffected.
	w := callOAuth2Responder(false, func(r *HTTPResponder) {
		r.Response(nil, &oauth2Err{status: http.StatusBadRequest, code: coreweb.OAuth2InvalidGrant, desc: "bad code"}, false)
	})
	body := decodeOAuth2(t, w.Body.Bytes())
	if body.Error != "" {
		t.Errorf("non-OAuth route should not emit an RFC error field, got %q", body.Error)
	}
}
