package command

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
	"testing"
)

func TestForgotPasswordUseCase(t *testing.T) {
	ctx := context.Background()

	newMod := func(repo *mockUserRepo, sender port.EmailSender) *usecase.Registry {
		mod := usecase.NewRegistry()
		mod.Register(ForgotPasswordCommand{}, NewForgotPasswordUseCase(define.Dependencies{
			UserRepo:    repo,
			EmailSender: sender,
		}))
		return mod
	}

	tests := []struct {
		name              string
		cmd               *ForgotPasswordCommand
		repo              *mockUserRepo
		emailSender       *mockEmailSender
		wantErrCode       coreerror.ErrCode
		wantEmailSent     bool
		wantTokenStored   bool
		wantSendAttempted bool
	}{
		{
			name:            "existing email — token stored and email sent",
			cmd:             &ForgotPasswordCommand{Email: "test@example.com"},
			repo:            newMockRepo(newTestUser()),
			emailSender:     &mockEmailSender{},
			wantEmailSent:   true,
			wantTokenStored: true,
		},
		{
			name:          "unknown email — no error, no email sent (no info leakage)",
			cmd:           &ForgotPasswordCommand{Email: "nobody@example.com"},
			repo:          newMockRepo(),
			emailSender:   &mockEmailSender{},
			wantEmailSent: false,
		},
		{
			name:        "invalid email format — validation failure",
			cmd:         &ForgotPasswordCommand{Email: "not-an-email"},
			repo:        newMockRepo(),
			emailSender: &mockEmailSender{},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing email — validation failure",
			cmd:         &ForgotPasswordCommand{},
			repo:        newMockRepo(),
			emailSender: &mockEmailSender{},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:          "userRepo.Save fails — logs error, returns nil (no info leakage)",
			cmd:           &ForgotPasswordCommand{Email: "test@example.com"},
			repo:          &mockUserRepo{users: map[string]*entity.User{"user-1": newTestUser()}, saveErr: errors.New("disk full")},
			emailSender:   &mockEmailSender{},
			wantEmailSent: false,
		},
		{
			name:              "email send fails — logs error, returns nil (no info leakage)",
			cmd:               &ForgotPasswordCommand{Email: "test@example.com"},
			repo:              newMockRepo(newTestUser()),
			emailSender:       &mockEmailSender{sendErr: errors.New("smtp timeout")},
			wantTokenStored:   true,
			wantEmailSent:     false,
			wantSendAttempted: true,
		},
		{
			name:          "FindByEmail DB error — silent no-op (no info leakage)",
			cmd:           &ForgotPasswordCommand{Email: "test@example.com"},
			repo:          &mockUserRepo{users: make(map[string]*entity.User), findByEmailErr: errors.New("db timeout")},
			emailSender:   &mockEmailSender{},
			wantEmailSent: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod := newMod(tc.repo, tc.emailSender)
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

			if tc.wantEmailSent {
				if tc.emailSender.sentTo != tc.cmd.Email {
					t.Errorf("sentTo = %q, want %q", tc.emailSender.sentTo, tc.cmd.Email)
				}
				if tc.emailSender.sentToken == "" {
					t.Error("expected non-empty sentToken")
				}
			} else if tc.emailSender.sentTo != "" {
				t.Errorf("expected no email, but sent to %q", tc.emailSender.sentTo)
			}

			if tc.wantSendAttempted {
				if tc.emailSender.attemptedTo != tc.cmd.Email {
					t.Errorf("attemptedTo = %q, want %q", tc.emailSender.attemptedTo, tc.cmd.Email)
				}
				if tc.emailSender.attemptedToken == "" {
					t.Error("attemptedToken must not be empty — use case must call the sender with the generated token")
				}
			}

			if tc.wantTokenStored {
				user, _ := tc.repo.FindByEmail(ctx, entity.DefaultTenantID, tc.cmd.Email)
				if user == nil {
					t.Fatal("user not found in repo")
				}
				if user.PasswordResetTokenHash == nil {
					t.Error("expected PasswordResetTokenHash to be set")
				}
				if user.IsResetTokenExpired() {
					t.Error("expected reset token to not be expired yet")
				}
				if tc.wantEmailSent && !user.ValidateResetToken(tc.emailSender.sentToken) {
					t.Error("emailed token does not validate against stored hash")
				}
			}
		})
	}

	t.Run("save error — original user not mutated in-memory", func(t *testing.T) {
		original := newTestUser()
		repo := &mockUserRepo{
			users:   map[string]*entity.User{"user-1": original},
			saveErr: errors.New("disk full"),
		}
		mod := newMod(repo, &mockEmailSender{})
		_, _ = mod.Dispatch(ctx, &ForgotPasswordCommand{Email: "test@example.com"})

		if original.PasswordResetTokenHash != nil {
			t.Error("in-memory PasswordResetTokenHash should be nil after save failure")
		}
	})

	t.Run("nil emailSender — token saved, no email, no error", func(t *testing.T) {
		repo := newMockRepo(newTestUser())
		mod := newMod(repo, nil)
		_, err := mod.Dispatch(ctx, &ForgotPasswordCommand{Email: "test@example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		user, _ := repo.FindByEmail(ctx, entity.DefaultTenantID, "test@example.com")
		if user == nil {
			t.Fatal("user not found")
		}
		if user.PasswordResetTokenHash == nil {
			t.Error("expected reset token to be stored even with nil emailSender")
		}
	})
}
