package command

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sync"
	"testing"
)

func TestCreateUserUseCase_Concurrent(t *testing.T) {
	ctx := context.Background()

	t.Run("concurrent duplicate email — exactly one success, one EmailDuplicated", func(t *testing.T) {
		repo := newMockRepo()
		validCmd := func() *CreateUserCommand {
			return &CreateUserCommand{Username: "newuser", Nickname: "newnick", Email: "new@example.com", Password: "Password1!"}
		}

		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				mod := usecase.NewRegistry()
				mod.Register(CreateUserCommand{}, NewCreateUserUseCase(define.Dependencies{UserRepo: repo}))
				_, errs[i] = mod.Dispatch(ctx, validCmd())
			}(i)
		}
		wg.Wait()

		successes, emailDup := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				successes++
			case func() bool {
				e, ok := err.(interface{ Code() coreerror.ErrCode })
				return ok && e.Code() == autherrors.EmailDuplicated
			}():
				emailDup++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if successes != 1 || emailDup != 1 {
			t.Errorf("want 1 success and 1 EmailDuplicated, got %d successes and %d email-duplicated", successes, emailDup)
		}
	})

	t.Run("duplicate username — both succeed (username is display data, not a uniqueness key)", func(t *testing.T) {
		repo := newMockRepo()
		mod := usecase.NewRegistry()
		mod.Register(CreateUserCommand{}, NewCreateUserUseCase(define.Dependencies{UserRepo: repo}))

		cmd1 := &CreateUserCommand{Username: "sharedname", Nickname: "nick1", Email: "user1@example.com", Password: "Password1!"}
		cmd2 := &CreateUserCommand{Username: "sharedname", Nickname: "nick2", Email: "user2@example.com", Password: "Password1!"}

		if _, err := mod.Dispatch(ctx, cmd1); err != nil {
			t.Fatalf("first user: unexpected error: %v", err)
		}
		if _, err := mod.Dispatch(ctx, cmd2); err != nil {
			t.Fatalf("second user with same username: unexpected error: %v", err)
		}
	})
}

func TestCreateUserUseCase(t *testing.T) {
	ctx := context.Background()

	validCmd := func() *CreateUserCommand {
		return &CreateUserCommand{
			Username: "newuser",
			Nickname: "newnick",
			Email:    "new@example.com",
			Password: "Password1!",
		}
	}

	tests := []struct {
		name        string
		cmd         *CreateUserCommand
		repo        *mockUserRepo
		wantErrCode coreerror.ErrCode
		wantEmail   string
	}{
		{
			name:      "success",
			cmd:       validCmd(),
			repo:      newMockRepo(),
			wantEmail: "new@example.com",
		},
		{
			name:        "email already exists",
			cmd:         func() *CreateUserCommand { c := validCmd(); c.Email = "test@example.com"; return c }(),
			repo:        newMockRepo(newTestUser()),
			wantErrCode: autherrors.EmailDuplicated,
		},
		{
			name:        "missing username — validation failure",
			cmd:         &CreateUserCommand{Nickname: "nick", Email: "a@b.com", Password: "Password1!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing nickname — validation failure",
			cmd:         &CreateUserCommand{Username: "u", Email: "a@b.com", Password: "Password1!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing email — validation failure",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Password: "Password1!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "invalid email format — validation failure",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Email: "not-an-email", Password: "Password1!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing password — validation failure",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Email: "a@b.com"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "backend error — CreateUserFailed",
			cmd:         validCmd(),
			repo:        &mockUserRepo{users: make(map[string]*entity.User), saveErr: errors.New("disk full")},
			wantErrCode: autherrors.CreateUserFailed,
		},
		{
			name: "repo returns conflict — EmailDuplicated",
			cmd:  validCmd(),
			repo: func() *mockUserRepo {
				existing := newTestUser()
				existing.Email = "new@example.com"
				return newMockRepo(existing)
			}(),
			wantErrCode: autherrors.EmailDuplicated,
		},
		{
			name:        "weak password — too short",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Email: "a@b.com", Password: "Ab1!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "weak password — no uppercase",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Email: "a@b.com", Password: "password1!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "weak password — no lowercase",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Email: "a@b.com", Password: "PASSWORD1!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "weak password — no digit",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Email: "a@b.com", Password: "Password!!"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "weak password — no special char",
			cmd:         &CreateUserCommand{Username: "u", Nickname: "n", Email: "a@b.com", Password: "Password1"},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod := usecase.NewRegistry()
			mod.Register(CreateUserCommand{}, NewCreateUserUseCase(define.Dependencies{UserRepo: tc.repo}))
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
			resp := result.(*define.CreateUserResponse)
			if resp.Email != tc.wantEmail {
				t.Fatalf("email = %q, want %q", resp.Email, tc.wantEmail)
			}
			if resp.Username != tc.cmd.Username {
				t.Errorf("username = %q, want %q", resp.Username, tc.cmd.Username)
			}
			if resp.Nickname != tc.cmd.Nickname {
				t.Errorf("nickname = %q, want %q", resp.Nickname, tc.cmd.Nickname)
			}

			// password must be stored as hash, not plaintext
			saved, _ := tc.repo.FindByEmail(ctx, tc.cmd.Email)
			if saved == nil {
				t.Fatal("user not found in repo after save")
			}
			if saved.Password == tc.cmd.Password {
				t.Error("password must be hashed, not stored in plaintext")
			}
			if err := saved.ValidatePassword(tc.cmd.Password); err != nil {
				t.Errorf("stored hash does not match original password: %v", err)
			}
			if saved.EmailVerified {
				t.Error("EmailVerified must be false for new user")
			}
		})
	}
}
