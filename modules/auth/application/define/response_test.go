package define

import (
	"net/http"
	"testing"

	"sc/modules/auth/domain/entity"
)

func TestGetAuthorizeResponse_Cookies(t *testing.T) {
	t.Run("cookie carries session ID with Lax SameSite and correct MaxAge", func(t *testing.T) {
		r := &GetAuthorizeResponse{SessionID: "session-123"}
		cookies := r.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("len(Cookies()) = %d, want 1", len(cookies))
		}
		c := cookies[0]
		if c.Name != CookieAuthorizeRequest {
			t.Errorf("Name = %q, want %q", c.Name, CookieAuthorizeRequest)
		}
		if c.Value != "session-123" {
			t.Errorf("Value = %q, want %q", c.Value, "session-123")
		}
		if c.MaxAge != int(entity.AuthorizeRequestTTL.Seconds()) {
			t.Errorf("MaxAge = %d, want %d", c.MaxAge, int(entity.AuthorizeRequestTTL.Seconds()))
		}
		if c.SameSite == nil || *c.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want Lax", c.SameSite)
		}
	})
}

func TestCreateAuthCodeResponse(t *testing.T) {
	t.Run("URL returns the redirect URL containing the auth code", func(t *testing.T) {
		r := &CreateAuthCodeResponse{RedirectURI: "http://localhost:3000/callback?code=abc123&state=xyz"}
		if got := r.URL(); got != "http://localhost:3000/callback?code=abc123&state=xyz" {
			t.Errorf("URL() = %q, want redirect URL with auth code", got)
		}
	})

	t.Run("Cookies clears the session cookie", func(t *testing.T) {
		r := &CreateAuthCodeResponse{}
		cookies := r.Cookies()
		if len(cookies) != 1 {
			t.Fatalf("len(Cookies()) = %d, want 1", len(cookies))
		}
		c := cookies[0]
		if c.Name != CookieAuthorizeRequest {
			t.Errorf("Name = %q, want %q", c.Name, CookieAuthorizeRequest)
		}
		if c.Value != "" {
			t.Errorf("Value = %q, want empty string", c.Value)
		}
		if c.MaxAge != -1 {
			t.Errorf("MaxAge = %d, want -1 (deletion)", c.MaxAge)
		}
		if c.SameSite == nil || *c.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want Lax", c.SameSite)
		}
	})
}

func TestGetSignInResponse_HTMLData(t *testing.T) {
	t.Run("CSRF token and title are keyed correctly in template data", func(t *testing.T) {
		r := &GetSignInResponse{CSRFToken: "tok-xyz"}
		data := r.HTMLData()
		if got, ok := data[HTMLKeyCsrfToken]; !ok || got != "tok-xyz" {
			t.Errorf("data[%q] = %v, want %q", HTMLKeyCsrfToken, got, "tok-xyz")
		}
		if got, ok := data[HTMLKeyTitle]; !ok || got != HTMLTitleSignIn {
			t.Errorf("data[%q] = %v, want %q", HTMLKeyTitle, got, HTMLTitleSignIn)
		}
	})

	t.Run("sign-in page opts out of browser storage", func(t *testing.T) {
		r := &GetSignInResponse{CSRFToken: "tok-xyz"}
		if !r.NoStore() {
			t.Error("NoStore() = false, want true")
		}
	})
}
