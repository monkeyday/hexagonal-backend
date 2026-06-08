package command

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"testing"
)

func TestUpdateProfileUseCase(t *testing.T) {
	ctx := context.Background()

	repoWithTwoUsers := func() *mockUserRepo {
		other, err := entity.NewUser(entity.UserArgs{
			Username: "other",
			Nickname: "othernick",
			Password: "Password1!",
			Email:    "other@example.com",
		})
		if err != nil {
			panic(err)
		}
		other.ID = "user-2"
		return newMockRepo(newTestUser(), other)
	}

	tests := []struct {
		name              string
		cmd               *UpdateProfileCommand
		repo              *mockUserRepo
		wantErrCode       coreerror.ErrCode
		wantNickname      string
		wantEmail         string
		wantUsername      string
		wantEmailVerified bool
		wantUserID        string
	}{
		{
			name:         "update nickname",
			cmd:          &UpdateProfileCommand{UserID: "user-1", Nickname: new("updated-nick")},
			repo:         newMockRepo(newTestUser()),
			wantNickname: "updated-nick",
			wantEmail:    "test@example.com",
			wantUsername: "testuser",
			wantUserID:   "user-1",
			// email unchanged → EmailVerified stays true
			wantEmailVerified: true,
		},
		{
			name:         "update email to unused address",
			cmd:          &UpdateProfileCommand{UserID: "user-1", Email: new("new@example.com")},
			repo:         newMockRepo(newTestUser()),
			wantNickname: "testnick",
			wantEmail:    "new@example.com",
			wantUsername: "testuser",
			wantUserID:   "user-1",
			// email changed → EmailVerified must be reset to false
			wantEmailVerified: false,
		},
		{
			name:              "update email to own current email — success",
			cmd:               &UpdateProfileCommand{UserID: "user-1", Email: new("test@example.com")},
			repo:              newMockRepo(newTestUser()),
			wantNickname:      "testnick",
			wantEmail:         "test@example.com",
			wantUsername:      "testuser",
			wantUserID:        "user-1",
			wantEmailVerified: true,
		},
		{
			name:              "update username",
			cmd:               &UpdateProfileCommand{UserID: "user-1", Username: new("newusername")},
			repo:              newMockRepo(newTestUser()),
			wantNickname:      "testnick",
			wantEmail:         "test@example.com",
			wantUsername:      "newusername",
			wantUserID:        "user-1",
			wantEmailVerified: true,
		},
		{
			name:              "update nickname and email together",
			cmd:               &UpdateProfileCommand{UserID: "user-1", Nickname: new("newnick"), Email: new("combo@example.com")},
			repo:              newMockRepo(newTestUser()),
			wantNickname:      "newnick",
			wantEmail:         "combo@example.com",
			wantUsername:      "testuser",
			wantUserID:        "user-1",
			wantEmailVerified: false,
		},
		{
			name:        "update email — duplicate",
			cmd:         &UpdateProfileCommand{UserID: "user-1", Email: new("other@example.com")},
			repo:        repoWithTwoUsers(),
			wantErrCode: autherrors.EmailDuplicated,
		},
		{
			name:        "user not found",
			cmd:         &UpdateProfileCommand{UserID: "no-such-id", Nickname: new("works")},
			repo:        newMockRepo(newTestUser()),
			wantErrCode: autherrors.InvalidToken,
		},
		{
			name:        "missing user_id — validation failure",
			cmd:         &UpdateProfileCommand{},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "invalid email format — validation failure",
			cmd:         &UpdateProfileCommand{UserID: "user-1", Email: new("not-an-email")},
			repo:        newMockRepo(newTestUser()),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "save error",
			cmd:  &UpdateProfileCommand{UserID: "user-1", Nickname: new("works")},
			repo: &mockUserRepo{
				users:   map[string]*entity.User{"user-1": newTestUser()},
				saveErr: errors.New("disk full"),
			},
			wantErrCode: autherrors.UpdateProfileFailed,
		},
		{
			name:        "FindByID error — update failed",
			cmd:         &UpdateProfileCommand{UserID: "user-1", Nickname: new("works")},
			repo:        &mockUserRepo{users: map[string]*entity.User{"user-1": newTestUser()}, findByIDErr: errors.New("db timeout")},
			wantErrCode: autherrors.UpdateProfileFailed,
		},
	}

	t.Run("save error — original user not mutated in-memory", func(t *testing.T) {
		original := newTestUser()
		repo := &mockUserRepo{
			users:   map[string]*entity.User{"user-1": original},
			saveErr: errors.New("disk full"),
		}
		mod := usecase.NewRegistry()
		mod.Register(UpdateProfileCommand{}, NewUpdateProfileUseCase(define.Dependencies{UserRepo: repo}))
		_, _ = mod.Dispatch(ctx, &UpdateProfileCommand{UserID: "user-1", Nickname: new("mutated-nick"), Email: new("mutated@example.com")})

		stored := repo.users["user-1"]
		if stored.Nickname != "testnick" {
			t.Errorf("in-memory nickname should be unchanged after save failure, got %q", stored.Nickname)
		}
		if stored.Email != "test@example.com" {
			t.Errorf("in-memory email should be unchanged after save failure, got %q", stored.Email)
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod := usecase.NewRegistry()
			mod.Register(UpdateProfileCommand{}, NewUpdateProfileUseCase(define.Dependencies{UserRepo: tc.repo}))
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
			resp := result.(*define.UpdateProfileResponse)
			if resp.Nickname != tc.wantNickname {
				t.Errorf("nickname = %q, want %q", resp.Nickname, tc.wantNickname)
			}
			if resp.Email != tc.wantEmail {
				t.Errorf("email = %q, want %q", resp.Email, tc.wantEmail)
			}
			if tc.wantUsername != "" && resp.Username != tc.wantUsername {
				t.Errorf("username = %q, want %q", resp.Username, tc.wantUsername)
			}
			if tc.wantUserID != "" && resp.UserID != tc.wantUserID {
				t.Errorf("user_id = %q, want %q", resp.UserID, tc.wantUserID)
			}
			if resp.EmailVerified != tc.wantEmailVerified {
				t.Errorf("email_verified = %v, want %v", resp.EmailVerified, tc.wantEmailVerified)
			}
			if resp.UpdatedAt == nil {
				t.Error("updated_at should be set")
			}
		})
	}
}
