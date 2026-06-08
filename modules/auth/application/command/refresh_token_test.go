package command

import (
	"context"
	"errors"
	"sync"

	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"testing"
	"time"
)

func TestRefreshTokenUseCase_Atomicity(t *testing.T) {
	ctx := context.Background()
	user := newTestUser()

	newValidRT := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid")})
	}

	t.Run("concurrent same-token refresh — exactly one succeeds", func(t *testing.T) {
		rtRepo := newMockRefreshTokenRepo(newValidRT())
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &transactionalMockUoW{rtRepo: rtRepo},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
		}))

		type result struct {
			resp any
			err  error
		}
		results := make([]result, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		for i := range results {
			i := i
			go func() {
				defer wg.Done()
				resp, err := mod.Dispatch(ctx, &RefreshTokenCommand{
					GrantType:    "refresh_token",
					ClientID:     "APP_ID",
					RefreshToken: "valid-refresh-token",
				})
				results[i] = result{resp, err}
			}()
		}
		wg.Wait()

		var successes, invalidToken int
		for _, r := range results {
			if r.err == nil {
				successes++
			} else if e, ok := r.err.(interface{ Code() coreerror.ErrCode }); ok && e.Code() == autherrors.InvalidRefreshToken {
				invalidToken++
			} else {
				t.Errorf("unexpected error: %v", r.err)
			}
		}
		if successes != 1 {
			t.Errorf("successes = %d, want 1", successes)
		}
		if invalidToken != 1 {
			t.Errorf("InvalidRefreshToken errors = %d, want 1", invalidToken)
		}
	})

	t.Run("rotation preserves AuthenticatedAt", func(t *testing.T) {
		rt := newValidRT()
		originalAuthAt := rt.AuthenticatedAt
		rtRepo := newMockRefreshTokenRepo(rt)
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &mockUoW{},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
		}))

		resp, err := mod.Dispatch(ctx, &RefreshTokenCommand{
			GrantType:    "refresh_token",
			ClientID:     "APP_ID",
			RefreshToken: "valid-refresh-token",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		newHash := entity.Hash(resp.(*define.TokenResponse).RefreshToken)
		newRT := rtRepo.tokens[newHash]
		if newRT == nil {
			t.Fatal("new refresh token not found in repo")
		}
		if !newRT.AuthenticatedAt.Equal(originalAuthAt) {
			t.Errorf("AuthenticatedAt not preserved across rotation: got %v, want %v", newRT.AuthenticatedAt, originalAuthAt)
		}
	})

	t.Run("Save fails — old token not revoked (transactional rollback)", func(t *testing.T) {
		rtRepo := &mockRefreshTokenRepo{
			tokens:  map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): newValidRT()},
			saveErr: errors.New("db error"),
		}
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &transactionalMockUoW{rtRepo: rtRepo},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
		}))

		_, err := mod.Dispatch(ctx, &RefreshTokenCommand{
			GrantType:    "refresh_token",
			ClientID:     "APP_ID",
			RefreshToken: "valid-refresh-token",
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// After rollback, old token must still be valid
		oldHash := entity.Hash("valid-refresh-token")
		if rt := rtRepo.tokens[oldHash]; rt == nil || rt.RevokedAt != nil {
			t.Error("old refresh token must remain unrevoked after failed rotation (rollback)")
		}
		// New token must not have been persisted
		if len(rtRepo.tokens) != 1 {
			t.Errorf("expected exactly 1 token in repo after rollback, got %d", len(rtRepo.tokens))
		}
	})
}

func TestRefreshTokenUseCase(t *testing.T) {
	ctx := context.Background()

	newValidRT := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid email profile phone")})
	}

	tests := []struct {
		name        string
		cmd         *RefreshTokenCommand
		jwt         *mockJwtService
		repo        *mockUserRepo
		rtRepo      *mockRefreshTokenRepo
		wantErrCode coreerror.ErrCode
		wantToken   string
	}{
		{
			name: "success",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
				ExpireSecs:   new(600),
			},
			jwt:       &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo:      newMockRepo(newTestUser()),
			rtRepo:    newMockRefreshTokenRepo(newValidRT()),
			wantToken: "new-access",
		},
		{
			name: "token not found",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "unknown-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name:        "missing grant_type — validation failure",
			cmd:         &RefreshTokenCommand{ClientID: "APP_ID", RefreshToken: "valid-refresh-token"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing client_id — validation failure",
			cmd:         &RefreshTokenCommand{GrantType: "refresh_token", RefreshToken: "valid-refresh-token"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing refresh_token — validation failure",
			cmd:         &RefreshTokenCommand{GrantType: "refresh_token", ClientID: "APP_ID"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "negative expire_secs — validation failure",
			cmd:         &RefreshTokenCommand{GrantType: "refresh_token", ClientID: "APP_ID", RefreshToken: "valid-refresh-token", ExpireSecs: new(-1)},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "genAccessToken fails",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessErr: errors.New("sign error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			name: "genRefreshToken fails",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshErr: errors.New("rand error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name: "RevokeByTokenHash fails — GenRefreshTokenFailed",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      &mockRefreshTokenRepo{tokens: map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): newValidRT()}, revokeByHashErr: errors.New("db error")},
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name: "Save fails — GenRefreshTokenFailed",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      &mockRefreshTokenRepo{tokens: map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): newValidRT()}, saveErr: errors.New("db error")},
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name: "user not found — invalid refresh token",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(), // no users
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "revoked token — invalid refresh token error",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:  &mockJwtService{},
			repo: newMockRepo(newTestUser()),
			rtRepo: func() *mockRefreshTokenRepo {
				rt := newValidRT()
				rt.RevokedAt = new(time.Now())
				return newMockRefreshTokenRepo(rt)
			}(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "expired token — invalid refresh token error",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:  &mockJwtService{},
			repo: newMockRepo(newTestUser()),
			rtRepo: func() *mockRefreshTokenRepo {
				rt := newValidRT()
				rt.ExpiresAt = time.Now().Add(-1 * time.Minute)
				return newMockRefreshTokenRepo(rt)
			}(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "genIDToken fails",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh", idTokenErr: errors.New("sign error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			// AuthenticatedAt < cutoff but CreatedAt > cutoff (post-rotation timestamp).
			// The check must use AuthenticatedAt; using CreatedAt would wrongly allow this token.
			name: "AuthenticatedAt before SessionsInvalidatedAt — rejected even if CreatedAt is after",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt: &mockJwtService{},
			repo: func() *mockUserRepo {
				u := newTestUser()
				cutoff := time.Now().Add(-30 * time.Minute)
				u.SessionsInvalidatedAt = &cutoff
				return newMockRepo(u)
			}(),
			rtRepo: func() *mockRefreshTokenRepo {
				rt := newValidRT()
				rt.AuthenticatedAt = time.Now().Add(-time.Hour) // original auth before cutoff
				// rt.CreatedAt remains time.Now() — after the cutoff
				return newMockRefreshTokenRepo(rt)
			}(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod := usecase.NewRegistry()
			mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
				UoW:              &mockUoW{},
				JWTSvc:           tc.jwt,
				UserRepo:         tc.repo,
				RefreshTokenRepo: tc.rtRepo,
			}))
			result, err := mod.Dispatch(ctx, tc.cmd)

			if tc.wantErrCode != 0 {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != tc.wantErrCode {
					t.Fatalf("got err_code %v, want %d", err, tc.wantErrCode)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			resp := result.(*define.TokenResponse)
			if resp.AccessToken != tc.wantToken {
				t.Fatalf("access_token = %q, want %q", resp.AccessToken, tc.wantToken)
			}
			if resp.RefreshToken == "" {
				t.Fatal("refresh_token should not be empty")
			}
			if resp.IDToken == "" {
				t.Fatal("id_token should not be empty")
			}

			// rotation: old token revoked, new token persisted, custom expire_secs honoured
			oldHash := entity.Hash("valid-refresh-token")
			if rt, _ := tc.rtRepo.FindByTokenHash(ctx, oldHash); rt == nil || rt.RevokedAt == nil {
				t.Error("old refresh token should be revoked after rotation")
			}
			newHash := entity.Hash(resp.RefreshToken)
			if _, _ = tc.rtRepo.FindByTokenHash(ctx, newHash); tc.rtRepo.tokens[newHash] == nil {
				t.Error("new refresh token should be persisted after rotation")
			}
			if tc.cmd.ExpireSecs != nil && tc.jwt.capturedAccessExpireSecs != *tc.cmd.ExpireSecs {
				t.Errorf("capturedAccessExpireSecs = %d, want %d", tc.jwt.capturedAccessExpireSecs, *tc.cmd.ExpireSecs)
			}
		})
	}
}
