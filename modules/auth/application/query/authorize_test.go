package query

import (
	"context"
	"fmt"
	"strings"
	"testing"

	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
)

func TestGetAuthorizeUseCase(t *testing.T) {
	ctx := context.Background()

	registry := newMockClientRegistry(t, "client-123", "https://app.example.com/callback")

	newMod := func() (*usecase.Registry, *mockCache) {
		mc := newMockCache()
		mod := usecase.NewRegistry()
		mod.Register(GetAuthorizeQuery{}, NewGetAuthorizeUseCase(define.Dependencies{
			Cache:          mc,
			ClientRegistry: registry,
		}))
		return mod, mc
	}

	tests := []struct {
		name        string
		cmd         *GetAuthorizeQuery
		wantErrCode coreerror.ErrCode
		checkState  func(t *testing.T, mc *mockCache, res *define.GetAuthorizeResponse)
	}{
		{
			name: "valid request — stores session in cache and returns session_id",
			cmd: &GetAuthorizeQuery{
				ResponseType:        "code",
				ClientID:            "client-123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "openid email",
				State:               new("state-xyz"),
				Nonce:               new("nonce-abc"),
				CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
				CodeChallengeMethod: new("S256"),
			},
			checkState: func(t *testing.T, mc *mockCache, res *define.GetAuthorizeResponse) {
				if res.SessionID == "" {
					t.Fatal("expected non-empty SessionID")
				}
				raw, ok := mc.items[fmt.Sprintf(define.AuthorizeRequestCacheKey, res.SessionID)]
				if !ok {
					t.Fatal("expected session to be stored in cache")
				}
				session := raw.(*entity.AuthorizeRequest)
				if session.ClientID != "client-123" {
					t.Errorf("session.ClientID = %q, want client-123", session.ClientID)
				}
				if session.RedirectURI != "https://app.example.com/callback" {
					t.Errorf("session.RedirectURI = %q, want https://app.example.com/callback", session.RedirectURI)
				}
				if session.State == nil || *session.State != "state-xyz" {
					t.Errorf("session.State = %v, want state-xyz", session.State)
				}
				if session.Nonce == nil || *session.Nonce != "nonce-abc" {
					t.Errorf("session.Nonce = %v, want nonce-abc", session.Nonce)
				}
				if session.CSRFToken == "" {
					t.Error("session.CSRFToken should be non-empty")
				}
				if session.FailedAttempts != 0 {
					t.Errorf("session.FailedAttempts = %d, want 0", session.FailedAttempts)
				}
				if res.URL() != "/sign-in" {
					t.Errorf("Redirect() = %q, want /sign-in", res.URL())
				}
				cookies := res.Cookies()
				if len(cookies) != 1 || cookies[0].Name != "auth_session" || cookies[0].Value != res.SessionID {
					t.Errorf("unexpected Cookies(): %v", cookies)
				}
				if cookies[0].MaxAge != int(entity.AuthorizeRequestTTL.Seconds()) {
					t.Errorf("cookie.MaxAge = %d, want %d", cookies[0].MaxAge, int(entity.AuthorizeRequestTTL.Seconds()))
				}
				if cookies[0].SameSite == nil {
					t.Error("cookie.SameSite should be set")
				}
			},
		},
		{
			name: "no state — session stored without state field",
			cmd: &GetAuthorizeQuery{
				ResponseType:        "code",
				ClientID:            "client-123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "openid",
				CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
				CodeChallengeMethod: new("S256"),
			},
			checkState: func(t *testing.T, mc *mockCache, res *define.GetAuthorizeResponse) {
				raw, ok := mc.items[fmt.Sprintf(define.AuthorizeRequestCacheKey, res.SessionID)]
				if !ok {
					t.Fatal("expected session in cache")
				}
				session := raw.(*entity.AuthorizeRequest)
				if session.State != nil {
					t.Errorf("expected nil State, got %v", session.State)
				}
			},
		},
		{
			name:        "redirect_uri not whitelisted — error",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://evil.com/cb", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "unknown client_id — rejected fail-closed",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "unknown", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing response_type",
			cmd:         &GetAuthorizeQuery{ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "unsupported response_type",
			cmd:         &GetAuthorizeQuery{ResponseType: "token", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantErrCode: autherrors.UnsupportedResponseType,
		},
		{
			name:        "missing client_id",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing redirect_uri",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing scope",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "scope without openid",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "email profile"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "PKCE with S256 is accepted",
			cmd: &GetAuthorizeQuery{
				ResponseType:        "code",
				ClientID:            "client-123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "openid",
				CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
				CodeChallengeMethod: new("S256"),
			},
			checkState: func(t *testing.T, mc *mockCache, res *define.GetAuthorizeResponse) {
				if res.SessionID == "" {
					t.Fatal("expected non-empty SessionID")
				}
				raw, ok := mc.items[fmt.Sprintf(define.AuthorizeRequestCacheKey, res.SessionID)]
				if !ok {
					t.Fatal("expected session in cache")
				}
				session := raw.(*entity.AuthorizeRequest)
				if session.CodeChallenge == nil || *session.CodeChallenge != "Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg" {
					t.Errorf("CodeChallenge = %v, want Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg", session.CodeChallenge)
				}
				if session.CodeChallengeMethod == nil || *session.CodeChallengeMethod != "S256" {
					t.Errorf("CodeChallengeMethod = %v, want S256", session.CodeChallengeMethod)
				}
			},
		},
		{
			name: "public client without code_challenge — rejected (PKCE mandatory)",
			cmd: &GetAuthorizeQuery{
				ResponseType: "code",
				ClientID:     "client-123",
				RedirectURI:  "https://app.example.com/callback",
				Scope:        "openid",
			},
			wantErrCode: autherrors.InvalidAuthRequest,
		},
		{
			name: "PKCE with plain method is rejected",
			cmd: &GetAuthorizeQuery{
				ResponseType:        "code",
				ClientID:            "client-123",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "openid",
				CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
				CodeChallengeMethod: new("plain"),
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "PKCE code_challenge without method is rejected",
			cmd: &GetAuthorizeQuery{
				ResponseType:  "code",
				ClientID:      "client-123",
				RedirectURI:   "https://app.example.com/callback",
				Scope:         "openid",
				CodeChallenge: new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "redirect_uri with fragment is rejected",
			cmd: &GetAuthorizeQuery{
				ResponseType: "code",
				ClientID:     "client-123",
				RedirectURI:  "https://app.example.com/callback#fragment",
				Scope:        "openid",
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "state exceeding 1024 bytes is rejected",
			cmd: &GetAuthorizeQuery{
				ResponseType: "code",
				ClientID:     "client-123",
				RedirectURI:  "https://app.example.com/callback",
				Scope:        "openid",
				State:        new(strings.Repeat("a", 1025)),
			},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "nonce exceeding 1024 bytes is rejected",
			cmd: &GetAuthorizeQuery{
				ResponseType: "code",
				ClientID:     "client-123",
				RedirectURI:  "https://app.example.com/callback",
				Scope:        "openid",
				Nonce:        new(strings.Repeat("n", 1025)),
			},
			wantErrCode: autherrors.InvalidArguments,
		},
	}

	t.Run("cache set failure — error returned", func(t *testing.T) {
		mc := newMockCache()
		mc.setErr = fmt.Errorf("redis down")
		mod := usecase.NewRegistry()
		mod.Register(GetAuthorizeQuery{}, NewGetAuthorizeUseCase(define.Dependencies{
			Cache:          mc,
			ClientRegistry: registry,
		}))
		_, err := mod.Dispatch(ctx, &GetAuthorizeQuery{
			ResponseType:        "code",
			ClientID:            "client-123",
			RedirectURI:         "https://app.example.com/callback",
			Scope:               "openid",
			CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
			CodeChallengeMethod: new("S256"),
		})
		if err == nil {
			t.Fatal("expected error on cache failure, got nil")
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod, mc := newMod()
			result, err := mod.Dispatch(ctx, tc.cmd)

			if tc.wantErrCode != 0 {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != tc.wantErrCode {
					t.Fatalf("got err %v, want err_code %d", err, tc.wantErrCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			res, ok := result.(*define.GetAuthorizeResponse)
			if !ok {
				t.Fatalf("expected *define.GetAuthorizeResponse, got %T", result)
			}
			if tc.checkState != nil {
				tc.checkState(t, mc, res)
			}
		})
	}
}
