package command

import (
	"context"
	"fmt"
	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"testing"
	"time"
)

func TestRevokeTokenUseCase(t *testing.T) {
	ctx := context.Background()

	testRefreshToken := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid email profile phone")})
	}

	newMod := func(jwtSvc *mockJwtService, cache *mockCache, repo *mockUserRepo, rtRepo *mockRefreshTokenRepo) *usecase.Registry {
		mod := usecase.NewRegistry()
		mod.Register(RevokeTokenCommand{}, NewRevokeTokenUseCase(define.Dependencies{
			UserRepo:         repo,
			JWTSvc:           jwtSvc,
			Cache:            cache,
			RefreshTokenRepo: rtRepo,
		}))
		return mod
	}

	assertRTRevoked := func(t *testing.T, rtRepo *mockRefreshTokenRepo, token string) {
		t.Helper()
		rt, _ := rtRepo.FindByTokenHash(ctx, entity.Hash(token))
		if rt == nil || rt.RevokedAt == nil {
			t.Error("refresh token should be marked revoked")
		}
	}

	assertRTNotRevoked := func(t *testing.T, rtRepo *mockRefreshTokenRepo, token string) {
		t.Helper()
		rt, _ := rtRepo.FindByTokenHash(ctx, entity.Hash(token))
		if rt != nil && rt.RevokedAt != nil {
			t.Error("refresh token should not be revoked")
		}
	}

	t.Run("revoke by refresh token (no hint)", func(t *testing.T) {
		rtRepo := newMockRefreshTokenRepo(testRefreshToken())
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{CallerID: "user-1", Token: "valid-refresh-token"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertRTRevoked(t, rtRepo, "valid-refresh-token")
	})

	t.Run("revoke by refresh token (explicit hint)", func(t *testing.T) {
		rtRepo := newMockRefreshTokenRepo(testRefreshToken())
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "valid-refresh-token",
			TokenTypeHint: new("refresh_token"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertRTRevoked(t, rtRepo, "valid-refresh-token")
	})

	t.Run("revoke access token — JTI blacklisted in cache", func(t *testing.T) {
		cache := newMockCache()
		jwtSvc := &mockJwtService{parseClaims: &corejwt.Claims{
			Subject:   "user-1",
			ID:        "jti-abc123",
			ExpiresAt: new(time.Now().Add(time.Hour)),
		}}
		_, err := newMod(jwtSvc, cache, newMockRepo(newTestUser()), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "bearer-token",
			TokenTypeHint: new("access_token"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		key := fmt.Sprintf(define.BlacklistCacheKey, "jti-abc123")
		if _, ok := cache.items[key]; !ok {
			t.Errorf("expected JTI %q in blacklist cache, but not found", key)
		}
	})

	t.Run("access token hint with refresh token value — RT is revoked (hint is advisory)", func(t *testing.T) {
		// token_type_hint is advisory; if AT parse fails the server must extend search to RT.
		rtRepo := newMockRefreshTokenRepo(testRefreshToken())
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "valid-refresh-token",
			TokenTypeHint: new("access_token"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertRTRevoked(t, rtRepo, "valid-refresh-token")
	})

	t.Run("refresh token hint with valid access token — AT blacklisted (hint is advisory)", func(t *testing.T) {
		// RT store has no matching entry; server must extend search to AT per RFC 7009 §2.1.
		cache := newMockCache()
		jwtSvc := &mockJwtService{parseClaims: &corejwt.Claims{
			Subject:   "user-1",
			ID:        "jti-rt-hint",
			ExpiresAt: new(time.Now().Add(time.Hour)),
		}}
		_, err := newMod(jwtSvc, cache, newMockRepo(newTestUser()), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "bearer-token",
			TokenTypeHint: new("refresh_token"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		key := fmt.Sprintf(define.BlacklistCacheKey, "jti-rt-hint")
		if _, ok := cache.items[key]; !ok {
			t.Errorf("expected JTI %q in blacklist cache after RT-hint miss, not found", key)
		}
	})

	t.Run("revoke by access token hint — no-op (mock JWT returns no claims)", func(t *testing.T) {
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "valid-access-token",
			TokenTypeHint: new("access_token"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("caller cannot revoke another user's token", func(t *testing.T) {
		rtRepo := newMockRefreshTokenRepo(testRefreshToken())
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID: "other-user",
			Token:    "valid-refresh-token",
		})
		if err != nil {
			t.Fatalf("cross-user revoke must be a silent no-op, got: %v", err)
		}
		assertRTNotRevoked(t, rtRepo, "valid-refresh-token")
	})

	t.Run("unknown token — not an error (RFC 7009)", func(t *testing.T) {
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{Token: "no-such-token"})
		if err != nil {
			t.Fatalf("unknown token must not return an error per RFC 7009, got: %v", err)
		}
	})

	t.Run("revokeByHashErr — propagated for caller-owned token", func(t *testing.T) {
		rtRepo := &mockRefreshTokenRepo{
			tokens:          map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): testRefreshToken()},
			revokeByHashErr: fmt.Errorf("db timeout"),
		}
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID: "user-1",
			Token:    "valid-refresh-token",
		})
		if err == nil {
			t.Fatal("expected error for storage failure on caller-owned token, got nil")
		}
	})

	t.Run("findByTokenHashErr with explicit refresh_token hint — propagated", func(t *testing.T) {
		rtRepo := &mockRefreshTokenRepo{
			tokens:             map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): testRefreshToken()},
			findByTokenHashErr: fmt.Errorf("db timeout"),
		}
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "valid-refresh-token",
			TokenTypeHint: new("refresh_token"),
		})
		if err == nil {
			t.Fatal("expected error for storage failure on FindByTokenHash with explicit hint, got nil")
		}
	})

	t.Run("findByTokenHashErr no hint + opaque token — RT storage error returned", func(t *testing.T) {
		// Simulate RT store outage: lookup fails and the token is not a parseable access token.
		// The endpoint must not return success while the refresh token remains usable.
		rtRepo := &mockRefreshTokenRepo{findByTokenHashErr: fmt.Errorf("db timeout")}
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID: "user-1",
			Token:    "opaque-refresh-token-value", // ParseJWT will return nil claims
		})
		if err == nil {
			t.Fatal("expected RT storage error to surface when token cannot be confirmed as a caller-owned access token, got nil")
		}
	})

	t.Run("findByTokenHashErr no hint + valid access token — falls through to blacklist", func(t *testing.T) {
		rtRepo := &mockRefreshTokenRepo{
			findByTokenHashErr: fmt.Errorf("db timeout"),
		}
		cache := newMockCache()
		jwtSvc := &mockJwtService{parseClaims: &corejwt.Claims{
			Subject:   "user-1",
			ID:        "jti-fallthrough",
			ExpiresAt: new(time.Now().Add(time.Hour)),
		}}
		_, err := newMod(jwtSvc, cache, newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID: "user-1",
			Token:    "bearer-token",
		})
		if err != nil {
			t.Fatalf("expected nil — access-token blacklist should succeed despite RT storage error, got: %v", err)
		}
		key := fmt.Sprintf(define.BlacklistCacheKey, "jti-fallthrough")
		if _, ok := cache.items[key]; !ok {
			t.Errorf("expected JTI %q in blacklist cache after fallthrough, not found", key)
		}
	})

	t.Run("cache.Set error on access token blacklist — propagated", func(t *testing.T) {
		cache := newMockCache()
		cache.setErr = fmt.Errorf("cache unavailable")
		jwtSvc := &mockJwtService{parseClaims: &corejwt.Claims{
			Subject:   "user-1",
			ID:        "jti-abc123",
			ExpiresAt: new(time.Now().Add(time.Hour)),
		}}
		_, err := newMod(jwtSvc, cache, newMockRepo(newTestUser()), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "bearer-token",
			TokenTypeHint: new("access_token"),
		})
		if err == nil {
			t.Fatal("expected error for cache failure on access token blacklist, got nil")
		}
	})

	t.Run("access_token hint + unparseable token + RT backend error — error returned", func(t *testing.T) {
		// AT parse fails (opaque token) and RT store is unavailable: neither path can confirm
		// revocation, so the storage error must surface rather than returning false success.
		rtRepo := &mockRefreshTokenRepo{findByTokenHashErr: fmt.Errorf("db timeout")}
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "opaque-token",
			TokenTypeHint: new("access_token"),
		})
		if err == nil {
			t.Fatal("expected RT storage error to surface when neither revocation path confirms the token, got nil")
		}
	})

	t.Run("access token with empty JTI — not blacklisted", func(t *testing.T) {
		cache := newMockCache()
		jwtSvc := &mockJwtService{parseClaims: &corejwt.Claims{
			Subject:   "user-1",
			ID:        "",
			ExpiresAt: new(time.Now().Add(time.Hour)),
		}}
		_, err := newMod(jwtSvc, cache, newMockRepo(newTestUser()), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{
			CallerID:      "user-1",
			Token:         "bearer-token",
			TokenTypeHint: new("access_token"),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := cache.items[fmt.Sprintf(define.BlacklistCacheKey, "")]; ok {
			t.Error("empty JTI must not be written to blacklist cache")
		}
	})

	t.Run("missing token — validation error", func(t *testing.T) {
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{})
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
		}
	})

	t.Run("invalid token_type_hint — validation error", func(t *testing.T) {
		_, err := newMod(&mockJwtService{}, newMockCache(), newMockRepo(), newMockRefreshTokenRepo()).Dispatch(ctx, &RevokeTokenCommand{
			Token:         "tok",
			TokenTypeHint: new("bad_hint"),
		})
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
		}
	})

	t.Run("second revoke is a no-op", func(t *testing.T) {
		rtRepo := newMockRefreshTokenRepo(testRefreshToken())
		mod := newMod(&mockJwtService{}, newMockCache(), newMockRepo(newTestUser()), rtRepo)
		if _, err := mod.Dispatch(ctx, &RevokeTokenCommand{CallerID: "user-1", Token: "valid-refresh-token"}); err != nil {
			t.Fatalf("first revoke failed: %v", err)
		}
		_, err := mod.Dispatch(ctx, &RevokeTokenCommand{CallerID: "user-1", Token: "valid-refresh-token"})
		if err != nil {
			t.Fatalf("second revoke must be a no-op, got: %v", err)
		}
	})
}
