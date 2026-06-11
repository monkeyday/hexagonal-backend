package command

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"testing"
	"time"
)

func TestExchangeCodeUseCase(t *testing.T) {
	user := newTestUser()

	newValidCode := func() *entity.AuthCode {
		return &entity.AuthCode{
			Code:        "valid-code",
			UserID:      user.ID,
			ClientID:    new(entity.ClientID("client-123")),
			RedirectURI: "https://app.example.com/callback",
			Scope:       entity.MustParseScope("openid email"),
			Nonce:       new("nonce-abc"),
			ExpiresAt:   time.Now().Add(entity.AuthCodeTTL),
		}
	}

	expiredCode := &entity.AuthCode{
		Code:        "expired-code",
		UserID:      user.ID,
		ClientID:    new(entity.ClientID("client-123")),
		RedirectURI: "https://app.example.com/callback",
		ExpiresAt:   time.Now().Add(-time.Minute),
	}

	newPublicPKCECode := func(userID entity.UserID) *entity.AuthCode {
		return &entity.AuthCode{
			Code:                "pub-pkce-code",
			UserID:              userID,
			ClientID:            new(entity.ClientID("public-client")),
			RedirectURI:         "https://app.example.com/callback",
			Scope:               entity.MustParseScope("openid"),
			CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"), // S256 of "verifier-123"
			CodeChallengeMethod: new("S256"),
			ExpiresAt:           time.Now().Add(entity.AuthCodeTTL),
		}
	}

	base := &ExchangeCodeCommand{
		Code:         "valid-code",
		ClientID:     "client-123",
		ClientSecret: testClientSecret,
		RedirectURI:  "https://app.example.com/callback",
		ExpireSecs:   new(3600),
	}

	tests := []struct {
		name             string
		cmd              *ExchangeCodeCommand
		jwtSvc           *mockJwtService
		userRepoOverride *mockUserRepo
		rtRepoOverride   *mockRefreshTokenRepo
		extraCodes       []*entity.AuthCode
		wantErrCode      coreerror.ErrCode
		wantAnyErr       bool
		wantRTPersisted  bool
		wantIDTokenNonce string
		check            func(t *testing.T, resp *define.TokenResponse)
	}{
		{
			name:             "valid code returns tokens",
			cmd:              base,
			jwtSvc:           &mockJwtService{accessToken: "new-access-token", refreshToken: "new-refresh-token"},
			wantRTPersisted:  true,
			wantIDTokenNonce: "nonce-abc",
			check: func(t *testing.T, resp *define.TokenResponse) {
				if resp.AccessToken == "" {
					t.Error("access_token must not be empty")
				}
				if resp.IDToken == "" {
					t.Error("id_token must not be empty")
				}
				if resp.RefreshToken == "" {
					t.Error("refresh_token must not be empty")
				}
				if resp.TokenType != define.TokenTypeBearer {
					t.Errorf("token_type = %q, want %q", resp.TokenType, define.TokenTypeBearer)
				}
				if resp.Scope != "openid email" {
					t.Errorf("scope = %q, want openid email", resp.Scope)
				}
				if resp.ExpiresIn != 3600 {
					t.Errorf("expires_in = %d, want 3600", resp.ExpiresIn)
				}
			},
		},
		{
			name:        "code not found returns error",
			cmd:         &ExchangeCodeCommand{Code: "unknown-code", ClientID: "client-123", ClientSecret: testClientSecret, RedirectURI: "https://app.example.com/callback"},
			jwtSvc:      &mockJwtService{},
			wantErrCode: autherrors.AuthCodeNotFound,
		},
		{
			name:        "expired code returns error",
			cmd:         &ExchangeCodeCommand{Code: "expired-code", ClientID: "client-123", ClientSecret: testClientSecret, RedirectURI: "https://app.example.com/callback"},
			jwtSvc:      &mockJwtService{},
			extraCodes:  []*entity.AuthCode{expiredCode},
			wantErrCode: autherrors.AuthCodeNotFound,
		},
		{
			name:        "unknown client_id — invalid_client",
			cmd:         &ExchangeCodeCommand{Code: "valid-code", ClientID: "wrong-client", RedirectURI: "https://app.example.com/callback"},
			jwtSvc:      &mockJwtService{},
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name:        "registered client_id not matching the code — invalid_grant",
			cmd:         &ExchangeCodeCommand{Code: "pub-pkce-code", ClientID: "client-123", ClientSecret: testClientSecret, RedirectURI: "https://app.example.com/callback", CodeVerifier: "verifier-123"},
			jwtSvc:      &mockJwtService{},
			extraCodes:  []*entity.AuthCode{newPublicPKCECode(user.ID)},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "redirect_uri mismatch returns error",
			cmd:         &ExchangeCodeCommand{Code: "valid-code", ClientID: "client-123", ClientSecret: testClientSecret, RedirectURI: "https://evil.example.com/callback"},
			jwtSvc:      &mockJwtService{},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:             "user not found — raw error returned",
			cmd:              base,
			jwtSvc:           &mockJwtService{accessToken: "tok", refreshToken: "rtok"},
			userRepoOverride: newMockRepo(), // user not in repo
			wantAnyErr:       true,
		},
		{
			name:        "genAccessToken fails",
			cmd:         base,
			jwtSvc:      &mockJwtService{accessErr: errors.New("sign error")},
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			name:        "genRefreshToken fails",
			cmd:         base,
			jwtSvc:      &mockJwtService{accessToken: "tok", refreshErr: errors.New("rand error")},
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name:        "genIDToken fails",
			cmd:         base,
			jwtSvc:      &mockJwtService{accessToken: "tok", refreshToken: "rtok", idTokenErr: errors.New("sign error")},
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			name:           "RT save fails — raw error returned",
			cmd:            base,
			jwtSvc:         &mockJwtService{accessToken: "tok", refreshToken: "rtok"},
			rtRepoOverride: &mockRefreshTokenRepo{tokens: make(map[string]*entity.RefreshToken), saveErr: errors.New("db error")},
			wantAnyErr:     true,
		},
		{
			name: "valid code with PKCE (S256) returns tokens",
			cmd: &ExchangeCodeCommand{
				Code:         "pkce-code",
				ClientID:     "client-123",
				ClientSecret: testClientSecret,
				RedirectURI:  "https://app.example.com/callback",
				CodeVerifier: "verifier-123",
			},
			jwtSvc: &mockJwtService{accessToken: "pkce-access", refreshToken: "pkce-refresh"},
			extraCodes: []*entity.AuthCode{
				{
					Code:                "pkce-code",
					UserID:              user.ID,
					ClientID:            new(entity.ClientID("client-123")),
					RedirectURI:         "https://app.example.com/callback",
					Scope:               entity.MustParseScope("openid"),
					CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"), // S256 of "verifier-123"
					CodeChallengeMethod: new("S256"),
					ExpiresAt:           time.Now().Add(entity.AuthCodeTTL),
				},
			},
			check: func(t *testing.T, resp *define.TokenResponse) {
				if resp.AccessToken != "pkce-access" {
					t.Errorf("got %s, want pkce-access", resp.AccessToken)
				}
			},
		},
		{
			name: "PKCE with plain method is rejected",
			cmd: &ExchangeCodeCommand{
				Code:         "pkce-plain-code",
				ClientID:     "client-123",
				ClientSecret: testClientSecret,
				RedirectURI:  "https://app.example.com/callback",
				CodeVerifier: "verifier-plain-123",
			},
			jwtSvc: &mockJwtService{},
			extraCodes: []*entity.AuthCode{
				{
					Code:                "pkce-plain-code",
					UserID:              user.ID,
					ClientID:            new(entity.ClientID("client-123")),
					RedirectURI:         "https://app.example.com/callback",
					Scope:               entity.MustParseScope("openid"),
					CodeChallenge:       new("verifier-plain-123"),
					CodeChallengeMethod: new("plain"),
					ExpiresAt:           time.Now().Add(entity.AuthCodeTTL),
				},
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "PKCE challenge present but verifier omitted",
			cmd: &ExchangeCodeCommand{
				Code:         "pkce-no-verifier",
				ClientID:     "client-123",
				ClientSecret: testClientSecret,
				RedirectURI:  "https://app.example.com/callback",
			},
			jwtSvc: &mockJwtService{},
			extraCodes: []*entity.AuthCode{
				{
					Code:                "pkce-no-verifier",
					UserID:              user.ID,
					ClientID:            new(entity.ClientID("client-123")),
					RedirectURI:         "https://app.example.com/callback",
					Scope:               entity.MustParseScope("openid"),
					CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
					CodeChallengeMethod: new("S256"),
					ExpiresAt:           time.Now().Add(entity.AuthCodeTTL),
				},
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "invalid code verifier for PKCE fails",
			cmd: &ExchangeCodeCommand{
				Code:         "pkce-code-fail",
				ClientID:     "client-123",
				ClientSecret: testClientSecret,
				RedirectURI:  "https://app.example.com/callback",
				CodeVerifier: "wrong-verifier",
			},
			jwtSvc: &mockJwtService{},
			extraCodes: []*entity.AuthCode{
				{
					Code:                "pkce-code-fail",
					UserID:              user.ID,
					ClientID:            new(entity.ClientID("client-123")),
					RedirectURI:         "https://app.example.com/callback",
					Scope:               entity.MustParseScope("openid"),
					CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
					CodeChallengeMethod: new("S256"),
					ExpiresAt:           time.Now().Add(entity.AuthCodeTTL),
				},
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "confidential client with wrong secret — invalid_client",
			cmd:         &ExchangeCodeCommand{Code: "valid-code", ClientID: "client-123", ClientSecret: "wrong-secret", RedirectURI: "https://app.example.com/callback"},
			jwtSvc:      &mockJwtService{},
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name:        "confidential client without secret — invalid_client",
			cmd:         &ExchangeCodeCommand{Code: "valid-code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback"},
			jwtSvc:      &mockJwtService{},
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name: "client_secret_basic client via Basic auth — tokens issued",
			cmd: &ExchangeCodeCommand{
				Code:              "basic-code",
				BasicClientID:     "basic-client",
				BasicClientSecret: testClientSecret,
				RedirectURI:       "https://app.example.com/callback",
			},
			jwtSvc: &mockJwtService{accessToken: "basic-access", refreshToken: "basic-refresh"},
			extraCodes: []*entity.AuthCode{
				{
					Code:        "basic-code",
					UserID:      user.ID,
					ClientID:    new(entity.ClientID("basic-client")),
					RedirectURI: "https://app.example.com/callback",
					Scope:       entity.MustParseScope("openid"),
					ExpiresAt:   time.Now().Add(entity.AuthCodeTTL),
				},
			},
			wantRTPersisted: true,
		},
		{
			name: "client_secret_post client via Basic auth — invalid_client (wrong channel)",
			cmd: &ExchangeCodeCommand{
				Code:              "valid-code",
				BasicClientID:     "client-123",
				BasicClientSecret: testClientSecret,
				RedirectURI:       "https://app.example.com/callback",
			},
			jwtSvc:      &mockJwtService{},
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name:        "public client presenting a secret — invalid_client",
			cmd:         &ExchangeCodeCommand{Code: "pub-pkce-code", ClientID: "public-client", ClientSecret: "anything", RedirectURI: "https://app.example.com/callback", CodeVerifier: "verifier-123"},
			jwtSvc:      &mockJwtService{},
			extraCodes:  []*entity.AuthCode{newPublicPKCECode(user.ID)},
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name: "public client with valid PKCE verifier — tokens issued",
			cmd: &ExchangeCodeCommand{
				Code:         "pub-pkce-code",
				ClientID:     "public-client",
				RedirectURI:  "https://app.example.com/callback",
				CodeVerifier: "verifier-123",
			},
			jwtSvc:          &mockJwtService{accessToken: "pub-access", refreshToken: "pub-refresh"},
			extraCodes:      []*entity.AuthCode{newPublicPKCECode(user.ID)},
			wantRTPersisted: true,
		},
		{
			name:   "public client, code issued without challenge — invalid_grant",
			cmd:    &ExchangeCodeCommand{Code: "pub-no-pkce", ClientID: "public-client", RedirectURI: "https://app.example.com/callback"},
			jwtSvc: &mockJwtService{},
			extraCodes: []*entity.AuthCode{
				{
					Code:        "pub-no-pkce",
					UserID:      user.ID,
					ClientID:    new(entity.ClientID("public-client")),
					RedirectURI: "https://app.example.com/callback",
					Scope:       entity.MustParseScope("openid"),
					ExpiresAt:   time.Now().Add(entity.AuthCodeTTL),
				},
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "client not allowed to use authorization_code grant — invalid_client",
			cmd:         &ExchangeCodeCommand{Code: "valid-code", ClientID: "password-only-client", ClientSecret: testClientSecret, RedirectURI: "https://app.example.com/callback"},
			jwtSvc:      &mockJwtService{},
			wantErrCode: autherrors.InvalidClient,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userRepo := tc.userRepoOverride
			if userRepo == nil {
				userRepo = newMockRepo(user)
			}
			rtRepo := tc.rtRepoOverride
			if rtRepo == nil {
				rtRepo = newMockRefreshTokenRepo()
			}
			mc := newMockCache().seed(fmt.Sprintf(define.AuthCodeCacheKey, "valid-code"), newValidCode())
			for _, c := range tc.extraCodes {
				mc.seed(fmt.Sprintf(define.AuthCodeCacheKey, c.Code), c)
			}
			uc := NewExchangeCodeUseCase(define.Dependencies{
				JWTSvc:           tc.jwtSvc,
				UserRepo:         userRepo,
				Cache:            mc,
				RefreshTokenRepo: rtRepo,
				ClientRegistry: newMockClientRegistry(
					newTestClient(t, "client-123", entity.ClientAuthSecretPost),
					newTestClient(t, "basic-client", entity.ClientAuthSecretBasic),
					newTestClient(t, "public-client", entity.ClientAuthNone),
					newTestClient(t, "password-only-client", entity.ClientAuthSecretPost, entity.GrantPassword),
				),
			})

			result, err := uc.Execute(context.Background(), tc.cmd)

			if tc.wantErrCode != 0 {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != tc.wantErrCode {
					t.Fatalf("got err_code %v, want %d", err, tc.wantErrCode)
				}
				return
			}
			if tc.wantAnyErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			resp := result.(*define.TokenResponse)
			if tc.check != nil {
				tc.check(t, resp)
			}
			if tc.wantRTPersisted {
				rtHash := entity.Hash(resp.RefreshToken)
				if rtRepo.tokens[rtHash] == nil {
					t.Error("refresh token should be persisted in the repository")
				}
				if rt := rtRepo.tokens[rtHash]; rt != nil && rt.UserID != user.ID {
					t.Errorf("RT.UserID = %q, want %q", rt.UserID, user.ID)
				}
			}
			if tc.wantIDTokenNonce != "" {
				if got := tc.jwtSvc.capturedIDTokenNonce; got != tc.wantIDTokenNonce {
					t.Errorf("GenIDToken nonce = %q, want %q", got, tc.wantIDTokenNonce)
				}
			}
		})
	}
}

func TestExchangeCodeOnlyOnce(t *testing.T) {
	user := newTestUser()
	mc := newMockCache()
	authCode := &entity.AuthCode{
		Code:        "one-time-code",
		UserID:      user.ID,
		ClientID:    new(entity.ClientID("client-123")),
		RedirectURI: "https://app.example.com/callback",
		Scope:       entity.MustParseScope("openid"),
		ExpiresAt:   time.Now().Add(entity.AuthCodeTTL),
	}
	mc.seed(fmt.Sprintf(define.AuthCodeCacheKey, "one-time-code"), authCode)

	uc := NewExchangeCodeUseCase(define.Dependencies{
		JWTSvc:           &mockJwtService{accessToken: "tok", refreshToken: "rtok"},
		UserRepo:         newMockRepo(user),
		Cache:            mc,
		RefreshTokenRepo: newMockRefreshTokenRepo(),
		ClientRegistry:   newMockClientRegistry(newTestClient(t, "client-123", entity.ClientAuthSecretPost)),
	})

	cmd := &ExchangeCodeCommand{Code: "one-time-code", ClientID: "client-123", ClientSecret: testClientSecret, RedirectURI: "https://app.example.com/callback"}

	if _, err := uc.Execute(context.Background(), cmd); err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}

	// code was consumed — second exchange must fail
	_, err := uc.Execute(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected error on second exchange (code reuse), got nil")
	}
	if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.AuthCodeNotFound {
		t.Fatalf("want AuthCodeNotFound on reuse, got %v", err)
	}
}

func TestExchangeCodeValidation(t *testing.T) {
	ctx := context.Background()
	mod := usecase.NewRegistry()
	mod.Register(ExchangeCodeCommand{}, NewExchangeCodeUseCase(define.Dependencies{
		JWTSvc:           &mockJwtService{},
		UserRepo:         newMockRepo(newTestUser()),
		Cache:            newMockCache(),
		RefreshTokenRepo: newMockRefreshTokenRepo(),
		ClientRegistry:   newMockClientRegistry(newTestClient(t, "client-123", entity.ClientAuthSecretPost)),
	}))

	cases := []struct {
		name string
		cmd  *ExchangeCodeCommand
	}{
		{"missing code", &ExchangeCodeCommand{ClientID: "client-123", RedirectURI: "https://app.example.com/callback"}},
		{"missing redirect_uri", &ExchangeCodeCommand{Code: "tok", ClientID: "client-123"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mod.Dispatch(ctx, tc.cmd)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
				t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
			}
		})
	}

	// client_id is no longer required by validation: a Basic-only client is
	// legitimate (RFC 6749 §2.3). No client on either channel → invalid_client.
	t.Run("no client on either channel — invalid_client", func(t *testing.T) {
		_, err := mod.Dispatch(ctx, &ExchangeCodeCommand{Code: "tok", RedirectURI: "https://app.example.com/callback"})
		if err == nil {
			t.Fatal("expected invalid_client, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidClient {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidClient, err)
		}
	})
}

func TestExchangeCodeCommand_RedirectURIIsNormalized(t *testing.T) {
	// Regression guard for finding #9: the redirect_uri compared at /token
	// must be normalized into the same canonical space as /authorize and the
	// client registry. The normalization itself happens in the binding layer.
	f, ok := reflect.TypeOf(ExchangeCodeCommand{}).FieldByName("RedirectURI")
	if !ok {
		t.Fatal("RedirectURI field not found")
	}
	if got := f.Tag.Get("normalize"); got != "uri" {
		t.Errorf(`RedirectURI normalize tag = %q, want "uri"`, got)
	}
}
