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

	seedRT := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "rt-token", Scope: entity.MustParseScope("openid")})
	}
	validAccessClaims := &corejwt.Claims{
		Subject:   "user-1",
		ID:        "jti-xyz",
		ExpiresAt: new(time.Now().Add(1 * time.Hour)),
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
			name: "valid bearer token — revokes refresh tokens, blacklists JTI, redirects",
			cmd: &LogoutCommand{
				AccessToken:           new("bearer-token"),
				PostLogoutRedirectURI: new(allowedURI),
			},
			jwt:                         &mockJwtService{parseClaims: validAccessClaims},
			postLogoutRedirectAllowlist: []string{allowedURI},
			wantRedirect:                allowedURI,
			wantTokensGone:              true,
			wantCookieCleared:           true,
			wantJTIBlacklisted:          fmt.Sprintf(define.BlacklistCacheKey, "jti-xyz"),
		},
		{
			name:               "valid bearer token, no redirect URI — revokes, empty redirect",
			cmd:                &LogoutCommand{AccessToken: new("bearer-token")},
			jwt:                &mockJwtService{parseClaims: validAccessClaims},
			wantRedirect:       "",
			wantTokensGone:     true,
			wantJTIBlacklisted: fmt.Sprintf(define.BlacklistCacheKey, "jti-xyz"),
		},
		{
			name: "no credentials (cross-site GET shape) — nothing revoked, still redirects",
			cmd: &LogoutCommand{
				PostLogoutRedirectURI: new(allowedURI),
			},
			jwt:                         &mockJwtService{},
			postLogoutRedirectAllowlist: []string{allowedURI},
			wantRedirect:                allowedURI,
			wantTokensUntoched:          true,
			wantCacheEmpty:              true,
			wantCookieCleared:           true,
		},
		{
			name:                        "invalid bearer token — nothing revoked, still redirects",
			cmd:                         &LogoutCommand{AccessToken: new("bad-token"), PostLogoutRedirectURI: new(allowedURI)},
			jwt:                         &mockJwtService{parseErr: errors.New("invalid token")},
			postLogoutRedirectAllowlist: []string{allowedURI},
			wantRedirect:                allowedURI,
			wantTokensUntoched:          true,
			wantCacheEmpty:              true,
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

func TestLogoutUseCase_RevokesOnlyCallerTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("bearer for user-1 — user-2 tokens untouched", func(t *testing.T) {
		rtUser1 := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "rt-user1", Scope: entity.MustParseScope("openid")})
		rtUser2 := entity.NewRefreshToken("user-2", "", &entity.IssuedTokens{RefreshToken: "rt-user2", Scope: entity.MustParseScope("openid")})
		rtRepo := newMockRefreshTokenRepo(rtUser1, rtUser2)

		deps := define.Dependencies{
			JWTSvc: &mockJwtService{
				parseClaims: &corejwt.Claims{Subject: "user-1", ID: "jti-1", ExpiresAt: new(time.Now().Add(time.Hour))},
			},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            newMockCache(),
			RefreshTokenRepo: rtRepo,
		}
		uc := NewLogoutUseCase(deps)

		if _, err := uc.Execute(ctx, &LogoutCommand{AccessToken: new("bearer-token")}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, rt := range rtRepo.tokens {
			if rt.UserID == "user-1" && rt.RevokedAt == nil {
				t.Error("expected user-1 refresh tokens to be revoked")
			}
			if rt.UserID == "user-2" && rt.RevokedAt != nil {
				t.Error("expected user-2 refresh tokens to be untouched")
			}
		}
	})
}
