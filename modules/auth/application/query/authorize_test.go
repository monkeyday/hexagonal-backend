package query

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/core/web"
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

	const validChallenge = "Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"

	tests := []struct {
		name string
		cmd  *GetAuthorizeQuery
		// wantErrCode asserts a direct error (no redirect): used when client_id or
		// redirect_uri is invalid/unregistered, per RFC 6749 §4.1.2.1.
		wantErrCode coreerror.ErrCode
		// wantRedirectErr asserts a redirect back to redirect_uri carrying this
		// RFC 6749 error code.
		wantRedirectErr string
		checkState      func(t *testing.T, mc *mockCache, res *define.GetAuthorizeResponse)
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
				CodeChallenge:       new(validChallenge),
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
				if session.State == nil || *session.State != "state-xyz" {
					t.Errorf("session.State = %v, want state-xyz", session.State)
				}
				if session.Nonce == nil || *session.Nonce != "nonce-abc" {
					t.Errorf("session.Nonce = %v, want nonce-abc", session.Nonce)
				}
				if session.CSRFToken == "" {
					t.Error("session.CSRFToken should be non-empty")
				}
				if res.URL() != "/sign-in" {
					t.Errorf("URL() = %q, want /sign-in", res.URL())
				}
				cookies := res.Cookies()
				if len(cookies) != 1 || cookies[0].Name != "auth_session" || cookies[0].Value != res.SessionID {
					t.Errorf("unexpected Cookies(): %v", cookies)
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
				CodeChallenge:       new(validChallenge),
				CodeChallengeMethod: new("S256"),
			},
			checkState: func(t *testing.T, mc *mockCache, res *define.GetAuthorizeResponse) {
				raw, ok := mc.items[fmt.Sprintf(define.AuthorizeRequestCacheKey, res.SessionID)]
				if !ok {
					t.Fatal("expected session in cache")
				}
				if session := raw.(*entity.AuthorizeRequest); session.State != nil {
					t.Errorf("expected nil State, got %v", session.State)
				}
			},
		},

		// ── direct errors: redirect_uri / client_id not trustworthy ──────────────
		{
			name:        "redirect_uri not whitelisted — direct error, no redirect",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://evil.com/cb", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "unknown client_id — direct error, fail-closed",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "unknown", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing client_id — direct error",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing redirect_uri — direct error",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "redirect_uri with fragment — direct error",
			cmd:         &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback#fragment", Scope: "openid"},
			wantErrCode: autherrors.InvalidArguments,
		},

		// ── redirect-errors: redirect_uri is registered (RFC 6749 §4.1.2.1) ──────
		{
			name:            "missing response_type — redirects with invalid_request",
			cmd:             &GetAuthorizeQuery{ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantRedirectErr: web.OAuth2InvalidRequest,
		},
		{
			name:            "unsupported response_type — redirects with unsupported_response_type",
			cmd:             &GetAuthorizeQuery{ResponseType: "token", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantRedirectErr: web.OAuth2UnsupportedResponseType,
		},
		{
			name:            "missing scope — redirects with invalid_scope",
			cmd:             &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback"},
			wantRedirectErr: web.OAuth2InvalidScope,
		},
		{
			name:            "scope without openid — redirects with invalid_scope",
			cmd:             &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "email profile"},
			wantRedirectErr: web.OAuth2InvalidScope,
		},
		{
			name:            "public client without code_challenge — redirects with invalid_request (PKCE mandatory)",
			cmd:             &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid"},
			wantRedirectErr: web.OAuth2InvalidRequest,
		},
		{
			name:            "PKCE plain method — redirects with invalid_request",
			cmd:             &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid", CodeChallenge: new(validChallenge), CodeChallengeMethod: new("plain")},
			wantRedirectErr: web.OAuth2InvalidRequest,
		},
		{
			name:            "PKCE code_challenge without method — redirects with invalid_request",
			cmd:             &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid", CodeChallenge: new(validChallenge)},
			wantRedirectErr: web.OAuth2InvalidRequest,
		},
		{
			name:            "state exceeding 1024 bytes — redirects with invalid_request",
			cmd:             &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid", CodeChallenge: new(validChallenge), CodeChallengeMethod: new("S256"), State: new(strings.Repeat("a", 1025))},
			wantRedirectErr: web.OAuth2InvalidRequest,
		},
		{
			name:            "nonce exceeding 1024 bytes — redirects with invalid_request",
			cmd:             &GetAuthorizeQuery{ResponseType: "code", ClientID: "client-123", RedirectURI: "https://app.example.com/callback", Scope: "openid", CodeChallenge: new(validChallenge), CodeChallengeMethod: new("S256"), Nonce: new(strings.Repeat("n", 1025))},
			wantRedirectErr: web.OAuth2InvalidRequest,
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
			CodeChallenge:       new(validChallenge),
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

			switch {
			case tc.wantErrCode != 0:
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != tc.wantErrCode {
					t.Fatalf("got err %v, want err_code %d", err, tc.wantErrCode)
				}
			case tc.wantRedirectErr != "":
				if err != nil {
					t.Fatalf("expected redirect result, got error: %v", err)
				}
				red, ok := result.(*define.AuthorizeErrorRedirect)
				if !ok {
					t.Fatalf("expected *define.AuthorizeErrorRedirect, got %T", result)
				}
				assertRedirectError(t, red.URL(), tc.cmd.RedirectURI, tc.wantRedirectErr, tc.cmd.State)
			default:
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
			}
		})
	}
}

// assertRedirectError verifies a §4.1.2.1 error redirect: same redirect_uri base,
// the expected error code, and the state echoed back when one was sent.
func assertRedirectError(t *testing.T, got, redirectURI, wantErr string, state *string) {
	t.Helper()
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("redirect URL not parseable: %v", err)
	}
	if base := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String(); base != redirectURI {
		t.Errorf("redirect base = %q, want %q", base, redirectURI)
	}
	if e := u.Query().Get("error"); e != wantErr {
		t.Errorf("error = %q, want %q", e, wantErr)
	}
	if state != nil && u.Query().Get("state") != *state {
		t.Errorf("state = %q, want %q", u.Query().Get("state"), *state)
	}
}
