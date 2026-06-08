package command

import (
	"context"
	"errors"
	"fmt"
	corejwt "sc/core/jwt"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	"testing"
	"time"
)

func TestLogoutUseCase(t *testing.T) {
	ctx := context.Background()

	validIDTokenClaims := &corejwt.IDTokenClaims{Subject: "user-1"}
	seedRT := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "rt-token", Scope: entity.MustParseScope("openid")})
	}

	const allowedURI = "https://app.example.com/logged-out"

	tests := []struct {
		name                        string
		cmd                         *LogoutCommand
		jwt                         *mockJwtService
		postLogoutRedirectAllowlist []string
		wantRedirect                string
		wantTokensGone              bool
		wantTokensUntoched          bool   // assert RT RevokedAt is still nil
		wantCookieCleared           bool   // assert LogoutResponse.Cookies() has MaxAge -1
		wantJTIBlacklisted          string // non-empty: assert this JTI key exists in cache
		wantCacheEmpty              bool   // assert nothing was written to cache
	}{
		{
			name: "valid token — revokes refresh tokens and redirects",
			cmd: &LogoutCommand{
				IDTokenHint:           new("valid-token"),
				PostLogoutRedirectURI: new(allowedURI),
			},
			jwt:                         &mockJwtService{parseIDTokenClaims: validIDTokenClaims},
			postLogoutRedirectAllowlist: []string{allowedURI},
			wantRedirect:                allowedURI,
			wantTokensGone:              true,
			wantCookieCleared:           true,
		},
		{
			name: "no credentials — skips revocation, still redirects",
			cmd: &LogoutCommand{
				PostLogoutRedirectURI: new(allowedURI),
			},
			jwt:                         &mockJwtService{},
			postLogoutRedirectAllowlist: []string{allowedURI},
			wantRedirect:                allowedURI,
			wantTokensUntoched:          true,
		},
		{
			name: "invalid token — best-effort, still redirects",
			cmd: &LogoutCommand{
				IDTokenHint:           new("bad-token"),
				PostLogoutRedirectURI: new(allowedURI),
			},
			jwt:                         &mockJwtService{parseIDTokenErr: errors.New("invalid token")},
			postLogoutRedirectAllowlist: []string{allowedURI},
			wantRedirect:                allowedURI,
			wantTokensUntoched:          true,
		},
		{
			name: "no redirect URI — returns empty string",
			cmd: &LogoutCommand{
				IDTokenHint: new("valid-token"),
			},
			jwt:            &mockJwtService{parseIDTokenClaims: validIDTokenClaims},
			wantRedirect:   "",
			wantTokensGone: true,
		},
		{
			name: "redirect URI not in allowlist — silently dropped",
			cmd: &LogoutCommand{
				PostLogoutRedirectURI: new("https://evil.example.com/steal"),
			},
			jwt:                         &mockJwtService{},
			postLogoutRedirectAllowlist: []string{allowedURI},
			wantRedirect:                "",
			wantTokensUntoched:          true,
		},
		{
			name: "empty allowlist — all redirect URIs dropped",
			cmd: &LogoutCommand{
				PostLogoutRedirectURI: new(allowedURI),
			},
			jwt:                         &mockJwtService{},
			postLogoutRedirectAllowlist: nil,
			wantRedirect:                "",
			wantTokensUntoched:          true,
		},
		{
			name:           "refresh token cookie only — revokes refresh tokens",
			cmd:            &LogoutCommand{RefreshToken: new("rt-token")},
			jwt:            &mockJwtService{},
			wantTokensGone: true,
		},
		{
			name:               "invalid refresh token cookie — skips revocation",
			cmd:                &LogoutCommand{RefreshToken: new("unknown-token")},
			jwt:                &mockJwtService{},
			wantTokensUntoched: true,
		},
		{
			name: "access token only — revokes refresh tokens and blacklists JTI",
			cmd:  &LogoutCommand{AccessToken: new("bearer-token")},
			jwt: &mockJwtService{parseClaims: &corejwt.Claims{
				Subject:   "user-1",
				ID:        "jti-xyz",
				ExpiresAt: new(time.Now().Add(1 * time.Hour)),
			}},
			wantTokensGone:     true,
			wantJTIBlacklisted: fmt.Sprintf(define.BlacklistCacheKey, "jti-xyz"),
		},
		{
			name: "active access token — JTI blacklisted in cache",
			cmd:  &LogoutCommand{AccessToken: new("bearer-token")},
			jwt: &mockJwtService{parseClaims: &corejwt.Claims{
				ID:        "jti-abc",
				ExpiresAt: new(time.Now().Add(1 * time.Hour)),
			}},
			wantJTIBlacklisted: fmt.Sprintf(define.BlacklistCacheKey, "jti-abc"),
		},
		{
			name: "expired access token — JTI not blacklisted",
			cmd:  &LogoutCommand{AccessToken: new("bearer-token")},
			jwt: &mockJwtService{parseClaims: &corejwt.Claims{
				ID:        "jti-abc",
				ExpiresAt: new(time.Now().Add(-1 * time.Hour)),
			}},
			wantCacheEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cache := newMockCache()
			rtRepo := newMockRefreshTokenRepo(seedRT())
			deps := define.Dependencies{
				JWTSvc:                      tc.jwt,
				UserRepo:                    newMockRepo(newTestUser()),
				Cache:                       cache,
				RefreshTokenRepo:            rtRepo,
				PostLogoutRedirectAllowlist: tc.postLogoutRedirectAllowlist,
			}
			uc := NewLogoutUseCase(deps)
			result, err := uc.Execute(ctx, tc.cmd)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			resp, _ := result.(*define.LogoutResponse)
			redirect := ""
			if resp != nil {
				redirect = resp.URL()
			}
			if redirect != tc.wantRedirect {
				t.Errorf("redirect = %q, want %q", redirect, tc.wantRedirect)
			}

			if tc.wantTokensGone {
				rts, _ := rtRepo.findAllForUser("user-1")
				for _, rt := range rts {
					if rt.RevokedAt == nil {
						t.Error("expected all refresh tokens to be revoked after logout")
					}
				}
			}

			if tc.wantTokensUntoched {
				rts, _ := rtRepo.findAllForUser("user-1")
				for _, rt := range rts {
					if rt.RevokedAt != nil {
						t.Error("expected refresh tokens to be untouched, but at least one was revoked")
					}
				}
			}

			if tc.wantCookieCleared {
				if resp == nil {
					t.Fatal("expected non-nil response for cookie check")
				}
				cookies := resp.Cookies()
				if len(cookies) == 0 || cookies[0].MaxAge != -1 {
					t.Errorf("expected cookie with MaxAge=-1, got %v", cookies)
				}
			}

			if tc.wantJTIBlacklisted != "" {
				if _, ok := cache.items[tc.wantJTIBlacklisted]; !ok {
					t.Errorf("expected JTI key %q in cache, but not found", tc.wantJTIBlacklisted)
				}
			}

			if tc.wantCacheEmpty && len(cache.items) != 0 {
				t.Errorf("expected empty cache, got %d entries", len(cache.items))
			}
		})
	}
}

func TestLogoutUseCase_SubjectPriority(t *testing.T) {
	ctx := context.Background()

	t.Run("both credentials with mismatched subjects — access token subject wins", func(t *testing.T) {
		rtUser1 := entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "rt-user1", Scope: entity.MustParseScope("openid")})
		rtUser2 := entity.NewRefreshToken("user-2", &entity.IssuedTokens{RefreshToken: "rt-user2", Scope: entity.MustParseScope("openid")})
		rtRepo := newMockRefreshTokenRepo(rtUser1, rtUser2)

		deps := define.Dependencies{
			JWTSvc: &mockJwtService{
				parseClaims:        &corejwt.Claims{Subject: "user-1", ID: "jti-1", ExpiresAt: new(time.Now().Add(time.Hour))},
				parseIDTokenClaims: &corejwt.IDTokenClaims{Subject: "user-2"},
			},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            newMockCache(),
			RefreshTokenRepo: rtRepo,
		}
		uc := NewLogoutUseCase(deps)
		cmd := &LogoutCommand{
			AccessToken: new("bearer-token"),
			IDTokenHint: new("id-token"),
		}

		if _, err := uc.Execute(ctx, cmd); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		user1Tokens, _ := rtRepo.findAllForUser("user-1")
		for _, rt := range user1Tokens {
			if rt.RevokedAt == nil {
				t.Error("expected user-1 refresh tokens to be revoked (access token subject wins)")
			}
		}

		user2Tokens, _ := rtRepo.findAllForUser("user-2")
		for _, rt := range user2Tokens {
			if rt.RevokedAt != nil {
				t.Error("expected user-2 refresh tokens to be untouched when access token subject is user-1")
			}
		}
	})
}

func TestLogoutUseCase_CookieRevocation(t *testing.T) {
	ctx := context.Background()

	t.Run("cookie only — revokes owner's tokens, leaves other users untouched", func(t *testing.T) {
		rtUser1 := entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "rt-user1", Scope: entity.MustParseScope("openid")})
		rtUser2 := entity.NewRefreshToken("user-2", &entity.IssuedTokens{RefreshToken: "rt-user2", Scope: entity.MustParseScope("openid")})
		rtRepo := newMockRefreshTokenRepo(rtUser1, rtUser2)

		deps := define.Dependencies{
			JWTSvc:           &mockJwtService{},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            newMockCache(),
			RefreshTokenRepo: rtRepo,
		}
		uc := NewLogoutUseCase(deps)

		if _, err := uc.Execute(ctx, &LogoutCommand{RefreshToken: new("rt-user1")}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, rt := range rtRepo.tokens {
			if rt.UserID == "user-1" && rt.RevokedAt == nil {
				t.Error("expected user-1 refresh token to be revoked via cookie lookup")
			}
			if rt.UserID == "user-2" && rt.RevokedAt != nil {
				t.Error("expected user-2 refresh token to be untouched")
			}
		}
	})

	t.Run("revoked cookie — skips revocation, not treated as identity proof", func(t *testing.T) {
		rt := entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "rt-revoked", Scope: entity.MustParseScope("openid")})
		now := time.Now()
		rt.RevokedAt = &now
		rtRepo := newMockRefreshTokenRepo(rt)

		deps := define.Dependencies{
			JWTSvc:           &mockJwtService{},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            newMockCache(),
			RefreshTokenRepo: rtRepo,
		}
		uc := NewLogoutUseCase(deps)

		if _, err := uc.Execute(ctx, &LogoutCommand{RefreshToken: new("rt-revoked")}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, stored := range rtRepo.tokens {
			if stored.UserID == "user-1" && stored.RevokedAt != &now {
				t.Error("expected user-1 token to remain in its prior revoked state, not re-revoked")
			}
		}
	})

	t.Run("expired cookie — skips revocation, not treated as identity proof", func(t *testing.T) {
		rt := entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "rt-expired", Scope: entity.MustParseScope("openid")})
		rt.ExpiresAt = time.Now().Add(-time.Hour)
		rtRepo := newMockRefreshTokenRepo(rt)

		deps := define.Dependencies{
			JWTSvc:           &mockJwtService{},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            newMockCache(),
			RefreshTokenRepo: rtRepo,
		}
		uc := NewLogoutUseCase(deps)

		if _, err := uc.Execute(ctx, &LogoutCommand{RefreshToken: new("rt-expired")}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, stored := range rtRepo.tokens {
			if stored.UserID == "user-1" && stored.RevokedAt != nil {
				t.Error("expected expired token to not trigger RevokeAllForUser")
			}
		}
	})
}
