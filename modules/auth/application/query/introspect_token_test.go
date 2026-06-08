package query

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	autherrors "sc/modules/auth/errors"
	"testing"
	"time"
)

func TestIntrospectTokenUseCase(t *testing.T) {
	ctx := context.Background()

	now := time.Now()
	validClaims := &corejwt.Claims{
		Subject:   "user-1",
		Issuer:    "https://auth.example.com",
		Audience:  []string{"APP_ID"},
		ExpiresAt: new(now.Add(time.Hour)),
		IssuedAt:  new(now),
		ID:        "jti-abc",
		Scope:     "openid email",
	}

	tests := []struct {
		name       string
		query      *IntrospectTokenQuery
		jwt        *mockJwtService
		cache      *mockCache
		wantActive bool
		wantSub    string
		wantScope  string
		wantJTI    string
		wantIssuer string
		wantAud    []string
		wantType   string
	}{
		{
			name:       "valid access token — active response with all fields",
			query:      &IntrospectTokenQuery{Token: "valid-token"},
			jwt:        &mockJwtService{parseClaims: validClaims},
			wantActive: true,
			wantSub:    "user-1",
			wantScope:  "openid email",
			wantJTI:    "jti-abc",
			wantIssuer: "https://auth.example.com",
			wantAud:    []string{"APP_ID"},
			wantType:   define.TokenTypeBearer,
		},
		{
			name:       "invalid token — inactive response",
			query:      &IntrospectTokenQuery{Token: "bad-token"},
			jwt:        &mockJwtService{parseErr: errors.New("invalid token")},
			wantActive: false,
		},
		{
			name:       "ParseJWT returns (nil, nil) — inactive",
			query:      &IntrospectTokenQuery{Token: "opaque-token"},
			jwt:        &mockJwtService{},
			wantActive: false,
		},
		{
			name:       "refresh_token hint with valid JWT — active (hint is advisory)",
			query:      &IntrospectTokenQuery{Token: "some-token", TokenTypeHint: new("refresh_token")},
			jwt:        &mockJwtService{parseClaims: validClaims},
			wantActive: true,
			wantSub:    "user-1",
			wantScope:  "openid email",
			wantJTI:    "jti-abc",
			wantIssuer: "https://auth.example.com",
			wantAud:    []string{"APP_ID"},
			wantType:   define.TokenTypeBearer,
		},
		{
			name:       "access_token hint — active response",
			query:      &IntrospectTokenQuery{Token: "valid-token", TokenTypeHint: new("access_token")},
			jwt:        &mockJwtService{parseClaims: validClaims},
			wantActive: true,
			wantSub:    "user-1",
			wantScope:  "openid email",
			wantJTI:    "jti-abc",
		},
		{
			name:       "revoked token — inactive (blacklisted JTI)",
			query:      &IntrospectTokenQuery{Token: "valid-token"},
			jwt:        &mockJwtService{parseClaims: validClaims},
			cache:      newMockCache().seed("blacklist:jti-abc", true),
			wantActive: false,
		},
		{
			name:       "cache error — fail-closed inactive",
			query:      &IntrospectTokenQuery{Token: "valid-token"},
			jwt:        &mockJwtService{parseClaims: validClaims},
			cache:      &mockCache{items: make(map[string]any), getErr: errors.New("cache unavailable")},
			wantActive: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := define.Dependencies{JWTSvc: tc.jwt}
			if tc.cache != nil {
				deps.Cache = tc.cache
			}
			uc := NewIntrospectTokenUseCase(deps)
			result, err := uc.Execute(ctx, tc.query)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			resp, ok := result.(*define.IntrospectResponse)
			if !ok {
				t.Fatalf("expected *define.IntrospectResponse, got %T", result)
			}

			if resp.Active != tc.wantActive {
				t.Errorf("Active = %v, want %v", resp.Active, tc.wantActive)
			}
			if tc.wantSub != "" && resp.Sub != tc.wantSub {
				t.Errorf("Sub = %q, want %q", resp.Sub, tc.wantSub)
			}
			if tc.wantScope != "" && resp.Scope != tc.wantScope {
				t.Errorf("Scope = %q, want %q", resp.Scope, tc.wantScope)
			}
			if tc.wantJTI != "" && resp.JWTID != tc.wantJTI {
				t.Errorf("JWTID = %q, want %q", resp.JWTID, tc.wantJTI)
			}
			if tc.wantIssuer != "" && resp.Issuer != tc.wantIssuer {
				t.Errorf("Issuer = %q, want %q", resp.Issuer, tc.wantIssuer)
			}
			if tc.wantAud != nil {
				if len(resp.Audience) != len(tc.wantAud) || (len(resp.Audience) > 0 && resp.Audience[0] != tc.wantAud[0]) {
					t.Errorf("Audience = %v, want %v", resp.Audience, tc.wantAud)
				}
			}
			if tc.wantType != "" && resp.TokenType != tc.wantType {
				t.Errorf("TokenType = %q, want %q", resp.TokenType, tc.wantType)
			}
			if tc.wantActive && resp.ExpiresAt == 0 {
				t.Error("ExpiresAt should be set for active token")
			}
			if tc.wantActive && resp.IssuedAt == 0 {
				t.Error("IssuedAt should be set for active token")
			}
		})
	}
}

func TestIntrospectTokenUseCase_Validation(t *testing.T) {
	ctx := context.Background()
	mod := usecase.NewRegistry()
	mod.Register(IntrospectTokenQuery{}, NewIntrospectTokenUseCase(define.Dependencies{JWTSvc: &mockJwtService{}}))

	t.Run("invalid token_type_hint — validation error", func(t *testing.T) {
		_, err := mod.Dispatch(ctx, &IntrospectTokenQuery{Token: "tok", TokenTypeHint: new("invalid_hint")})
		if err == nil {
			t.Fatal("expected validation error for invalid token_type_hint, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
		}
	})

	t.Run("missing token — validation error", func(t *testing.T) {
		_, err := mod.Dispatch(ctx, &IntrospectTokenQuery{})
		if err == nil {
			t.Fatal("expected validation error for missing token, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
		}
	})
}
