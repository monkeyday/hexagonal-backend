package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// mockJwtService implements TokenParser for auth middleware tests.
type mockJwtService struct {
	claims   *corejwt.Claims
	parseErr error
}

func (m *mockJwtService) ParseJWT(_ string) (*corejwt.Claims, error) {
	return m.claims, m.parseErr
}

// mockCache implements corecache.ReadErrorCache for auth middleware tests.
type mockCache struct {
	items     map[string]any
	getErrErr error // if set, GetErr returns this error
}

func newMockCache(revokedJTIs ...string) *mockCache {
	m := &mockCache{items: make(map[string]any)}
	for _, jti := range revokedJTIs {
		m.items["blacklist:"+jti] = true
	}
	return m
}

func (m *mockCache) Set(_ context.Context, key string, value any, _ *time.Duration) error {
	m.items[key] = value
	return nil
}
func (m *mockCache) Get(_ context.Context, key string, _ any) bool {
	_, ok := m.items[key]
	return ok
}
func (m *mockCache) GetErr(_ context.Context, key string, _ any) (bool, error) {
	if m.getErrErr != nil {
		return false, m.getErrErr
	}
	_, ok := m.items[key]
	return ok, nil
}
func (m *mockCache) GetAndDelete(_ context.Context, key string, _ any) bool {
	_, ok := m.items[key]
	if ok {
		delete(m.items, key)
	}
	return ok
}
func (m *mockCache) Delete(_ context.Context, key string)                      { delete(m.items, key) }
func (m *mockCache) Incr(_ context.Context, _ string) (int64, error)           { return 0, nil }
func (m *mockCache) Expire(_ context.Context, _ string, _ time.Duration) error { return nil }

func newExtractTokenRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/logout", ExtractAccessToken(), func(c *gin.Context) {
		token, exists := c.Get(TokenKey)
		c.JSON(http.StatusOK, gin.H{"token": token, "exists": exists})
	})
	return r
}

func TestExtractAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		wantTokenSet   bool
		wantTokenValue string
	}{
		{
			name:           "valid Bearer token — sets token in context",
			authHeader:     "Bearer my-access-token",
			wantTokenSet:   true,
			wantTokenValue: "my-access-token",
		},
		{
			name:           "lowercase bearer — sets token in context",
			authHeader:     "bearer my-access-token",
			wantTokenSet:   true,
			wantTokenValue: "my-access-token",
		},
		{
			name:           "uppercase BEARER — sets token in context",
			authHeader:     "BEARER my-access-token",
			wantTokenSet:   true,
			wantTokenValue: "my-access-token",
		},
		{
			name:           "extra whitespace after scheme — token trimmed and set",
			authHeader:     "Bearer   my-access-token",
			wantTokenSet:   true,
			wantTokenValue: "my-access-token",
		},
		{
			name:         "no Authorization header — passes through, no token set",
			authHeader:   "",
			wantTokenSet: false,
		},
		{
			name:         "Bearer with empty token — passes through, no token set",
			authHeader:   "Bearer ",
			wantTokenSet: false,
		},
		{
			name:         "wrong scheme — passes through, no token set",
			authHeader:   "Basic dXNlcjpwYXNz",
			wantTokenSet: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newExtractTokenRouter()
			req := httptest.NewRequest(http.MethodGet, "/logout", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("ExtractAccessToken should never reject — got status %d", w.Code)
			}
			if tc.wantTokenSet {
				assertBodyContains(t, w.Body.Bytes(), tc.wantTokenValue)
			} else {
				assertBodyContains(t, w.Body.Bytes(), `"exists":false`)
			}
		})
	}
}

func newAuthRouter(svc TokenParser, c *mockCache) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", Authenticate(svc, c), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id":      c.GetString(UserIdKey),
			"access_token": c.GetString(TokenKey),
		})
	})
	return r
}

func TestAuthenticate(t *testing.T) {
	exp := new(time.Now().Add(time.Hour))
	validClaims := &corejwt.Claims{Subject: "user-42", Issuer: "test-issuer"}
	revokedClaims := &corejwt.Claims{
		Subject:   "user-42",
		Issuer:    "test-issuer",
		ID:        "revoked-jti",
		ExpiresAt: exp,
	}

	tests := []struct {
		name        string
		authHeader  string
		svc         *mockJwtService
		cache       *mockCache
		wantStatus  int
		wantErrCode coreerror.ErrCode
		wantUserID  string
	}{
		{
			name:       "valid token — sets context and passes through",
			authHeader: "Bearer valid-token",
			svc:        &mockJwtService{claims: validClaims},
			cache:      newMockCache(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:       "lowercase bearer — authenticates",
			authHeader: "bearer valid-token",
			svc:        &mockJwtService{claims: validClaims},
			cache:      newMockCache(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:       "uppercase BEARER — authenticates",
			authHeader: "BEARER valid-token",
			svc:        &mockJwtService{claims: validClaims},
			cache:      newMockCache(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:       "extra whitespace after scheme — token trimmed and authenticates",
			authHeader: "Bearer   valid-token",
			svc:        &mockJwtService{claims: validClaims},
			cache:      newMockCache(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:        "missing Authorization header — 401",
			authHeader:  "",
			svc:         &mockJwtService{claims: validClaims},
			cache:       newMockCache(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "header too short (no token after Bearer) — 401",
			authHeader:  "Bearer ",
			svc:         &mockJwtService{claims: validClaims},
			cache:       newMockCache(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "wrong scheme (Basic) — ParseJWT rejects non-JWT — 401",
			authHeader:  "Basic dXNlcjpwYXNz",
			svc:         &mockJwtService{parseErr: errors.New("token contains an invalid number of segments")},
			cache:       newMockCache(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "ParseJWT fails — 401",
			authHeader:  "Bearer bad-token",
			svc:         &mockJwtService{parseErr: errors.New("signature invalid")},
			cache:       newMockCache(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "ParseJWT returns nil claims — 401",
			authHeader:  "Bearer nil-claims",
			svc:         &mockJwtService{claims: nil},
			cache:       newMockCache(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "revoked JTI — 401",
			authHeader:  "Bearer revoked-token",
			svc:         &mockJwtService{claims: revokedClaims},
			cache:       newMockCache("revoked-jti"),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "cache unavailable during blacklist check — fail closed 401",
			authHeader:  "Bearer valid-token",
			svc:         &mockJwtService{claims: revokedClaims},
			cache:       &mockCache{items: make(map[string]any), getErrErr: errors.New("redis unavailable")},
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newAuthRouter(tc.svc, tc.cache)
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("WWW-Authenticate = %q, want %q", got, "Bearer")
				}
			}
			if tc.wantErrCode != 0 {
				assertErrCode(t, w.Body.Bytes(), tc.wantErrCode)
			}
			if tc.wantUserID != "" {
				assertBodyContains(t, w.Body.Bytes(), tc.wantUserID)
			}
		})
	}
}
