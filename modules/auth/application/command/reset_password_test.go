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

func TestResetPasswordUseCase(t *testing.T) {
	ctx := context.Background()

	newUserWithResetToken := func(rawToken string, expired bool) *mockUserRepo {
		u := newTestUser()
		ttl := 15 * time.Minute
		if expired {
			ttl = -1 * time.Minute
		}
		u.SetPasswordResetToken(rawToken, ttl)
		return newMockRepo(u)
	}

	const rawToken = "valid-raw-token"
	const newPassword = "NewP@ssw0rd"

	tests := []struct {
		name           string
		cmd            *ResetPasswordCommand
		repo           *mockUserRepo
		rtRepo         *mockRefreshTokenRepo
		wantErrCode    coreerror.ErrCode
		wantRevoked    bool
		wantRTsRevoked bool
	}{
		{
			name:           "valid token and strong password — success",
			cmd:            &ResetPasswordCommand{Token: rawToken, Password: newPassword},
			repo:           newUserWithResetToken(rawToken, false),
			rtRepo:         newMockRefreshTokenRepo(entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "rt-token", Scope: entity.MustParseScope("openid")})),
			wantRevoked:    true,
			wantRTsRevoked: true,
		},
		{
			name:        "unknown token — not found error",
			cmd:         &ResetPasswordCommand{Token: "wrong-token", Password: newPassword},
			repo:        newUserWithResetToken(rawToken, false),
			wantErrCode: autherrors.PasswordResetTokenNotFound,
		},
		{
			name:        "expired token — expired error",
			cmd:         &ResetPasswordCommand{Token: rawToken, Password: newPassword},
			repo:        newUserWithResetToken(rawToken, true),
			wantErrCode: autherrors.PasswordResetTokenExpired,
		},
		{
			name:        "weak new password — weak password error",
			cmd:         &ResetPasswordCommand{Token: rawToken, Password: "weak"},
			repo:        newUserWithResetToken(rawToken, false),
			wantErrCode: autherrors.WeakPassword,
		},
		{
			name:        "missing token field — validation error",
			cmd:         &ResetPasswordCommand{Password: newPassword},
			repo:        newMockRepo(newTestUser()),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing password field — validation error",
			cmd:         &ResetPasswordCommand{Token: rawToken},
			repo:        newMockRepo(newTestUser()),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "RevokeAllForUser fails — success returned (best-effort, error logged)",
			cmd:         &ResetPasswordCommand{Token: rawToken, Password: newPassword},
			repo:        newUserWithResetToken(rawToken, false),
			rtRepo:      &mockRefreshTokenRepo{tokens: make(map[string]*entity.RefreshToken), revokeAllErr: errors.New("db timeout")},
			wantRevoked: true,
		},
		{
			name: "update error — reset password failed",
			cmd:  &ResetPasswordCommand{Token: rawToken, Password: newPassword},
			repo: func() *mockUserRepo {
				r := newUserWithResetToken(rawToken, false)
				r.updateByTokenHashErr = errors.New("disk full")
				return r
			}(),
			wantErrCode: autherrors.ResetPasswordFailed,
		},
	}

	t.Run("RevokeAllForUser fails — success returned and password change committed", func(t *testing.T) {
		repo := newUserWithResetToken(rawToken, false)
		mod := usecase.NewRegistry()
		mod.Register(ResetPasswordCommand{}, NewResetPasswordUseCase(define.Dependencies{
			UserRepo:         repo,
			RefreshTokenRepo: &mockRefreshTokenRepo{tokens: make(map[string]*entity.RefreshToken), revokeAllErr: errors.New("db timeout")},
			UoW:              &mockUoW{},
		}))
		_, err := mod.Dispatch(ctx, &ResetPasswordCommand{Token: rawToken, Password: newPassword})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		user, _ := repo.FindByID(ctx, "user-1")
		if user == nil {
			t.Fatal("user not found")
		}
		if user.PasswordResetTokenHash != nil {
			t.Error("reset token should be cleared")
		}
		if err := user.ValidatePassword(newPassword); err != nil {
			t.Errorf("new password should work: %v", err)
		}
	})

	t.Run("concurrent reuse — exactly one succeeds, one gets PasswordResetTokenNotFound", func(t *testing.T) {
		repo := newUserWithResetToken(rawToken, false)
		rtRepo := newMockRefreshTokenRepo()

		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				mod := usecase.NewRegistry()
				mod.Register(ResetPasswordCommand{}, NewResetPasswordUseCase(define.Dependencies{
					UserRepo:         repo,
					RefreshTokenRepo: rtRepo,
					UoW:              &mockUoW{},
				}))
				_, errs[i] = mod.Dispatch(ctx, &ResetPasswordCommand{Token: rawToken, Password: newPassword})
			}(i)
		}
		wg.Wait()

		successes, notFound := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				successes++
			case func() bool {
				e, ok := err.(interface{ Code() coreerror.ErrCode })
				return ok && e.Code() == autherrors.PasswordResetTokenNotFound
			}():
				notFound++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if successes != 1 || notFound != 1 {
			t.Errorf("want 1 success and 1 PasswordResetTokenNotFound, got %d successes and %d not-found", successes, notFound)
		}
	})

	t.Run("closure error — original user not mutated in-memory", func(t *testing.T) {
		original := newTestUser()
		original.SetPasswordResetToken(rawToken, 15*time.Minute)
		origPasswordHash := original.Password
		repo := &mockUserRepo{users: map[string]*entity.User{"user-1": original}}
		mod := usecase.NewRegistry()
		mod.Register(ResetPasswordCommand{}, NewResetPasswordUseCase(define.Dependencies{
			UserRepo:         repo,
			RefreshTokenRepo: newMockRefreshTokenRepo(),
			UoW:              &mockUoW{},
		}))
		_, _ = mod.Dispatch(ctx, &ResetPasswordCommand{Token: rawToken, Password: "weak"})

		if original.Password != origPasswordHash {
			t.Error("original user password should not be mutated after closure error")
		}
		if original.PasswordResetTokenHash == nil {
			t.Error("original user should still have reset token after closure error")
		}
	})

	t.Run("RevokeAllForUser fails — SessionsInvalidatedAt still set (security gate is the timestamp, not revocation)", func(t *testing.T) {
		repo := newUserWithResetToken(rawToken, false)
		mod := usecase.NewRegistry()
		mod.Register(ResetPasswordCommand{}, NewResetPasswordUseCase(define.Dependencies{
			UserRepo:         repo,
			RefreshTokenRepo: &mockRefreshTokenRepo{tokens: make(map[string]*entity.RefreshToken), revokeAllErr: errors.New("db timeout")},
			UoW:              &mockUoW{},
		}))
		_, err := mod.Dispatch(ctx, &ResetPasswordCommand{Token: rawToken, Password: newPassword})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		user, _ := repo.FindByID(ctx, "user-1")
		if user == nil {
			t.Fatal("user not found")
		}
		if user.SessionsInvalidatedAt == nil {
			t.Error("SessionsInvalidatedAt must be set even when RevokeAllForUser fails")
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rtRepo := tc.rtRepo
			if rtRepo == nil {
				rtRepo = newMockRefreshTokenRepo()
			}
			mod := usecase.NewRegistry()
			mod.Register(ResetPasswordCommand{}, NewResetPasswordUseCase(define.Dependencies{
				UserRepo:         tc.repo,
				RefreshTokenRepo: rtRepo,
				UoW:              &mockUoW{},
			}))
			_, err := mod.Dispatch(ctx, tc.cmd)

			if tc.wantErrCode != 0 {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != tc.wantErrCode {
					t.Fatalf("err_code = %v, want %d", err, tc.wantErrCode)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantRevoked {
				user, _ := tc.repo.FindByID(ctx, "user-1")
				if user == nil {
					t.Fatal("user not found")
				}
				if user.PasswordResetTokenHash != nil {
					t.Error("reset token hash should be cleared after use")
				}
				if user.PasswordResetExpiresAt != nil {
					t.Error("reset token expiry should be cleared after use")
				}
				if user.SessionsInvalidatedAt == nil {
					t.Error("SessionsInvalidatedAt must be set after password reset")
				}
				if err := user.ValidatePassword(newPassword); err != nil {
					t.Errorf("new password should work: %v", err)
				}
				if err := user.ValidatePassword("Password1!"); err == nil {
					t.Error("old password should no longer work after reset")
				}
			}

			if tc.wantRTsRevoked {
				rts, _ := rtRepo.findAllForUser("user-1")
				for _, rt := range rts {
					if rt.RevokedAt == nil {
						t.Error("refresh token should be revoked after password reset")
					}
				}
			}
		})
	}
}
