package query

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

func TestGetTokenUseCase(t *testing.T) {
	ctx := context.Background()

	defaultAllowlist := []string{"openid", "email", "profile", "phone"}

	tests := []struct {
		name        string
		cmd         *GetTokenQuery
		jwt         *mockJwtService
		repo        *mockUserRepo
		rtRepo      *mockRefreshTokenRepo
		wantErrCode coreerror.ErrCode
		wantToken   string
		wantScope   string
		wantExpires int
	}{
		{
			name:      "success — no scope defaults to full allowlist",
			cmd:       &GetTokenQuery{Email: "test@example.com", Password: "Password1!"},
			jwt:       &mockJwtService{accessToken: "tok-access", refreshToken: "tok-refresh"},
			repo:      newMockRepo(newTestUser()),
			rtRepo:    newMockRefreshTokenRepo(),
			wantToken: "tok-access",
			wantScope: "openid email profile phone",
		},
		{
			name:      "success — valid scope subset",
			cmd:       &GetTokenQuery{Email: "test@example.com", Password: "Password1!", Scope: new("openid email")},
			jwt:       &mockJwtService{accessToken: "tok-access", refreshToken: "tok-refresh"},
			repo:      newMockRepo(newTestUser()),
			rtRepo:    newMockRefreshTokenRepo(),
			wantToken: "tok-access",
			wantScope: "openid email",
		},
		{
			name:        "success — custom expire_secs",
			cmd:         &GetTokenQuery{Email: "test@example.com", Password: "Password1!", ExpireSecs: new(3600)},
			jwt:         &mockJwtService{accessToken: "tok-access", refreshToken: "tok-refresh"},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantToken:   "tok-access",
			wantExpires: 3600,
		},
		{
			name:        "invalid scope",
			cmd:         &GetTokenQuery{Email: "test@example.com", Password: "Password1!", Scope: new("openid admin")},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "invalid email format — validation failure",
			cmd:         &GetTokenQuery{Email: "not-an-email", Password: "Password1!"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "user not found",
			cmd:         &GetTokenQuery{Email: "nobody@example.com", Password: "Password1!"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidEmailOrPassword,
		},
		{
			name:        "wrong password",
			cmd:         &GetTokenQuery{Email: "test@example.com", Password: "wrongpassword"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidEmailOrPassword,
		},
		{
			name:        "missing email — validation failure",
			cmd:         &GetTokenQuery{Password: "Password1!"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing password — validation failure",
			cmd:         &GetTokenQuery{Email: "test@example.com"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "genAccessToken fails",
			cmd:         &GetTokenQuery{Email: "test@example.com", Password: "Password1!"},
			jwt:         &mockJwtService{accessErr: errors.New("sign error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			name:        "genRefreshToken fails",
			cmd:         &GetTokenQuery{Email: "test@example.com", Password: "Password1!"},
			jwt:         &mockJwtService{accessToken: "tok-access", refreshErr: errors.New("rand error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name:        "genIDToken fails",
			cmd:         &GetTokenQuery{Email: "test@example.com", Password: "Password1!"},
			jwt:         &mockJwtService{accessToken: "tok-access", refreshToken: "tok-refresh", idTokenErr: errors.New("sign error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			name:        "RT save fails — GenTokenFailed",
			cmd:         &GetTokenQuery{Email: "test@example.com", Password: "Password1!"},
			jwt:         &mockJwtService{accessToken: "tok-access", refreshToken: "tok-refresh"},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      &mockRefreshTokenRepo{tokens: make(map[string]*entity.RefreshToken), saveErr: errors.New("db error")},
			wantErrCode: autherrors.GenTokenFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod := usecase.NewRegistry()
			mod.Register(GetTokenQuery{}, NewGetTokenUseCase(define.Dependencies{
				JWTSvc:           tc.jwt,
				UserRepo:         tc.repo,
				RefreshTokenRepo: tc.rtRepo,
				ScopeAllowlist:   defaultAllowlist,
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
			if resp.TokenType != define.TokenTypeBearer {
				t.Fatalf("token_type = %q, want %q", resp.TokenType, define.TokenTypeBearer)
			}
			if tc.wantScope != "" && resp.Scope != tc.wantScope {
				t.Fatalf("scope = %q, want %q", resp.Scope, tc.wantScope)
			}
			if tc.wantExpires != 0 && resp.ExpiresIn != tc.wantExpires {
				t.Errorf("expires_in = %d, want %d", resp.ExpiresIn, tc.wantExpires)
			}

			// refresh token must be persisted
			rtHash := entity.Hash(resp.RefreshToken)
			if tc.rtRepo.tokens[rtHash] == nil {
				t.Error("refresh token should be persisted in the repository")
			}
			if tc.jwt.capturedAccessUserID != "user-1" {
				t.Errorf("capturedAccessUserID = %q, want user-1", tc.jwt.capturedAccessUserID)
			}
		})
	}
}
