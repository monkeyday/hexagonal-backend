package query

import (
	"context"
	"errors"
	"testing"

	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
)

func TestGetProfileUseCase(t *testing.T) {
	ctx := context.Background()
	user := newTestUser()
	dbErr := errors.New("db timeout")

	tests := []struct {
		name              string
		query             *GetProfileQuery
		repo              *mockUserRepo
		wantErrCode       coreerror.ErrCode
		wantRawErr        error
		wantEmail         string
		wantNickname      string
		wantEmailVerified bool
	}{
		{
			name:              "success",
			query:             &GetProfileQuery{UserID: string(user.ID)},
			repo:              newMockRepo(user),
			wantEmail:         user.Email,
			wantNickname:      user.Nickname,
			wantEmailVerified: user.EmailVerified,
		},
		{
			name:        "user not found",
			query:       &GetProfileQuery{UserID: "no-such-id"},
			repo:        newMockRepo(user),
			wantErrCode: autherrors.InvalidToken,
		},
		{
			name:        "missing user_id — validation failure",
			query:       &GetProfileQuery{},
			repo:        newMockRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "FindByID returns (nil, nil) — treated as not found",
			query:       &GetProfileQuery{UserID: "user-1"},
			repo:        &mockUserRepo{users: map[string]*entity.User{"user-1": nil}},
			wantErrCode: autherrors.InvalidToken,
		},
		{
			name:  "repository error — surfaced as-is",
			query: &GetProfileQuery{UserID: string(user.ID)},
			repo: func() *mockUserRepo {
				r := newMockRepo()
				r.findByIDErr = dbErr
				return r
			}(),
			wantRawErr: dbErr,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod := usecase.NewRegistry()
			mod.Register(GetProfileQuery{}, NewGetProfileUseCase(define.Dependencies{UserRepo: tc.repo}))
			result, err := mod.Dispatch(ctx, tc.query)

			if tc.wantRawErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tc.wantRawErr) {
					t.Fatalf("got err %v, want wrapping %v", err, tc.wantRawErr)
				}
				return
			}

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
			resp := result.(*define.GetProfileResponse)
			if resp.Email != tc.wantEmail {
				t.Fatalf("email = %q, want %q", resp.Email, tc.wantEmail)
			}
			if resp.Sub != string(user.ID) {
				t.Fatalf("sub = %q, want %q", resp.Sub, user.ID)
			}
			if resp.PreferredUsername != user.Username {
				t.Fatalf("preferred_username = %q, want %q", resp.PreferredUsername, user.Username)
			}
			if resp.Nickname != tc.wantNickname {
				t.Errorf("nickname = %q, want %q", resp.Nickname, tc.wantNickname)
			}
			if resp.EmailVerified != tc.wantEmailVerified {
				t.Errorf("email_verified = %v, want %v", resp.EmailVerified, tc.wantEmailVerified)
			}
		})
	}
}
