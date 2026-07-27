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

// mockRevocationChecker implements RevocationChecker for auth middleware tests.
type mockRevocationChecker struct {
	revoked          map[string]bool // revoked JTIs
	revokedGrants    map[string]bool // revoked grant IDs
	invalidatedUsers map[string]bool // users whose sessions are invalidated (all tokens)
	err              error           // if set, IsRevoked returns this error for any call
}

func newMockRevocationChecker(revokedJTIs ...string) *mockRevocationChecker {
	m := &mockRevocationChecker{
		revoked:          make(map[string]bool),
		revokedGrants:    make(map[string]bool),
		invalidatedUsers: make(map[string]bool),
	}
	for _, jti := range revokedJTIs {
		m.revoked[jti] = true
	}
	return m
}

func (m *mockRevocationChecker) IsRevoked(_ context.Context, claims *corejwt.Claims) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	if m.revoked[claims.ID] {
		return true, nil
	}
	if claims.GrantID != "" && m.revokedGrants[claims.GrantID] {
		return true, nil
	}
	if m.invalidatedUsers[claims.Subject] {
		return true, nil
	}
	return false, nil
}

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

func newAuthRouter(svc TokenParser, rev *mockRevocationChecker) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/protected", Authenticate(svc, rev), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id":      c.GetString(UserIdKey),
			"access_token": c.GetString(TokenKey),
			"grant_id":     c.GetString(GrantIdKey),
		})
	})
	return r
}

func TestAuthenticate(t *testing.T) {
	exp := new(time.Now().Add(time.Hour))
	validClaims := &corejwt.Claims{Subject: "user-42", Issuer: "test-issuer", ID: "valid-jti"}
	noJTIClaims := &corejwt.Claims{Subject: "user-42", Issuer: "test-issuer"}
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
		rev         *mockRevocationChecker
		wantStatus  int
		wantErrCode coreerror.ErrCode
		wantUserID  string
	}{
		{
			name:       "valid token — sets context and passes through",
			authHeader: "Bearer valid-token",
			svc:        &mockJwtService{claims: validClaims},
			rev:        newMockRevocationChecker(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:       "lowercase bearer — authenticates",
			authHeader: "bearer valid-token",
			svc:        &mockJwtService{claims: validClaims},
			rev:        newMockRevocationChecker(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:       "uppercase BEARER — authenticates",
			authHeader: "BEARER valid-token",
			svc:        &mockJwtService{claims: validClaims},
			rev:        newMockRevocationChecker(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:       "extra whitespace after scheme — token trimmed and authenticates",
			authHeader: "Bearer   valid-token",
			svc:        &mockJwtService{claims: validClaims},
			rev:        newMockRevocationChecker(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:        "missing Authorization header — 401",
			authHeader:  "",
			svc:         &mockJwtService{claims: validClaims},
			rev:         newMockRevocationChecker(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "header too short (no token after Bearer) — 401",
			authHeader:  "Bearer ",
			svc:         &mockJwtService{claims: validClaims},
			rev:         newMockRevocationChecker(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "wrong scheme (Basic) — ParseJWT rejects non-JWT — 401",
			authHeader:  "Basic dXNlcjpwYXNz",
			svc:         &mockJwtService{parseErr: errors.New("token contains an invalid number of segments")},
			rev:         newMockRevocationChecker(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "ParseJWT fails — 401",
			authHeader:  "Bearer bad-token",
			svc:         &mockJwtService{parseErr: errors.New("signature invalid")},
			rev:         newMockRevocationChecker(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "ParseJWT returns nil claims — 401",
			authHeader:  "Bearer nil-claims",
			svc:         &mockJwtService{claims: nil},
			rev:         newMockRevocationChecker(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "token without jti — rejected, cannot be blacklist-checked — 401",
			authHeader:  "Bearer no-jti-token",
			svc:         &mockJwtService{claims: noJTIClaims},
			rev:         newMockRevocationChecker(),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "revoked JTI — 401",
			authHeader:  "Bearer revoked-token",
			svc:         &mockJwtService{claims: revokedClaims},
			rev:         newMockRevocationChecker("revoked-jti"),
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:        "cache unavailable during blacklist check — fail closed 401",
			authHeader:  "Bearer valid-token",
			svc:         &mockJwtService{claims: revokedClaims},
			rev:         &mockRevocationChecker{err: errors.New("redis unavailable")},
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:       "token whose grant is revoked — 401 even though JTI is clean",
			authHeader: "Bearer valid-token",
			svc: &mockJwtService{claims: &corejwt.Claims{
				Subject: "user-42", ID: "clean-jti", GrantID: "revoked-grant",
			}},
			rev: &mockRevocationChecker{
				revoked:       map[string]bool{},
				revokedGrants: map[string]bool{"revoked-grant": true},
			},
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:       "legacy token (no sid) with clean jti — authenticates",
			authHeader: "Bearer valid-token",
			svc:        &mockJwtService{claims: &corejwt.Claims{Subject: "user-42", ID: "clean-jti-2"}},
			rev:        newMockRevocationChecker(),
			wantStatus: http.StatusOK,
			wantUserID: "user-42",
		},
		{
			name:       "cache error on grant check — fail-closed 401",
			authHeader: "Bearer valid-token",
			svc: &mockJwtService{claims: &corejwt.Claims{
				Subject: "user-42", ID: "jti-grant-err", GrantID: "some-grant",
			}},
			rev: &mockRevocationChecker{
				revoked:          map[string]bool{},
				revokedGrants:    map[string]bool{},
				invalidatedUsers: map[string]bool{},
				err:              errors.New("cache unavailable"),
			},
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
		{
			name:       "sessions invalidated for user — 401 even though JTI and grant are clean",
			authHeader: "Bearer valid-token",
			svc: &mockJwtService{claims: &corejwt.Claims{
				Subject: "user-42", ID: "clean-jti-3", GrantID: "clean-grant",
				IssuedAt: new(time.Now()),
			}},
			rev: &mockRevocationChecker{
				revoked:          map[string]bool{},
				revokedGrants:    map[string]bool{},
				invalidatedUsers: map[string]bool{"user-42": true},
			},
			wantStatus:  http.StatusUnauthorized,
			wantErrCode: coreerror.Unauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newAuthRouter(tc.svc, tc.rev)
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

func TestAuthenticate_GrantIdKey(t *testing.T) {
	t.Run("token with sid — GrantIdKey set in context", func(t *testing.T) {
		claims := &corejwt.Claims{Subject: "user-42", Issuer: "test-issuer", ID: "jti-1", GrantID: "grant-abc"}
		r := newAuthRouter(&mockJwtService{claims: claims}, newMockRevocationChecker())
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		assertBodyContains(t, w.Body.Bytes(), "grant-abc")
	})

	t.Run("token without sid (legacy) — authenticates, GrantIdKey empty", func(t *testing.T) {
		claims := &corejwt.Claims{Subject: "user-42", Issuer: "test-issuer", ID: "jti-2"}
		r := newAuthRouter(&mockJwtService{claims: claims}, newMockRevocationChecker())
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("legacy token without sid must still authenticate, got status %d", w.Code)
		}
		assertBodyContains(t, w.Body.Bytes(), `"grant_id":""`)
	})
}
