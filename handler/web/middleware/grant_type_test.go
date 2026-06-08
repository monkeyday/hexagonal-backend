package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newGrantTypeRouter(allowed []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/token", GrantType(allowed), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"grant_type": c.GetString(GrantTypeKey)})
	})
	return r
}

func TestGrantType(t *testing.T) {
	tests := []struct {
		name          string
		allowed       []string
		body          string
		contentType   string
		wantCode      int
		wantGrantType string
	}{
		{
			name:          "form: grant_type present",
			body:          "grant_type=authorization_code&code=abc",
			contentType:   "application/x-www-form-urlencoded",
			wantCode:      http.StatusOK,
			wantGrantType: "authorization_code",
		},
		{
			name:        "form: grant_type absent",
			body:        "email=a%40b.com&password=secret",
			contentType: "application/x-www-form-urlencoded",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "empty body",
			body:        "",
			contentType: "application/x-www-form-urlencoded",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:          "JSON: grant_type present",
			body:          `{"grant_type":"password","email":"x@y.com"}`,
			contentType:   "application/json",
			wantCode:      http.StatusOK,
			wantGrantType: "password",
		},
		{
			name:        "JSON: grant_type absent",
			body:        `{"email":"x@y.com","password":"secret"}`,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:          "allowlist: value in set passes",
			allowed:       []string{"password", "refresh_token"},
			body:          "grant_type=password",
			contentType:   "application/x-www-form-urlencoded",
			wantCode:      http.StatusOK,
			wantGrantType: "password",
		},
		{
			name:        "allowlist: value not in set rejected",
			allowed:     []string{"password", "refresh_token"},
			body:        "grant_type=client_credentials",
			contentType: "application/x-www-form-urlencoded",
			wantCode:    http.StatusBadRequest,
		},
	}

	t.Run("JSON body is reset and fully readable downstream", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.POST("/token", GrantType(nil), func(c *gin.Context) {
			var payload struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(c.Request.Body).Decode(&payload); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"grant_type": c.GetString(GrantTypeKey),
				"email":      payload.Email,
				"password":   payload.Password,
			})
		})

		body := `{"grant_type":"password","email":"x@y.com","password":"secret"}`
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body)
		}
		var resp struct {
			GrantType string `json:"grant_type"`
			Email     string `json:"email"`
			Password  string `json:"password"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.GrantType != "password" {
			t.Errorf("grant_type = %q, want %q", resp.GrantType, "password")
		}
		if resp.Email != "x@y.com" {
			t.Errorf("email = %q, want %q", resp.Email, "x@y.com")
		}
		if resp.Password != "secret" {
			t.Errorf("password = %q, want %q", resp.Password, "secret")
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newGrantTypeRouter(tc.allowed)
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			var resp struct {
				GrantType string `json:"grant_type"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if resp.GrantType != tc.wantGrantType {
				t.Errorf("grant_type = %q, want %q", resp.GrantType, tc.wantGrantType)
			}
		})
	}
}
