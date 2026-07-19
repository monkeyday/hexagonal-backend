package query

import (
	"context"
	"fmt"
	"testing"

	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
)

func mustNewSession(t *testing.T, args entity.AuthorizeRequestArgs) *entity.AuthorizeRequest {
	t.Helper()
	s, err := entity.NewAuthorizeRequest(args)
	if err != nil {
		t.Fatalf("setup: NewAuthorizeRequest: %v", err)
	}
	return s
}

func TestGetSignInUseCase(t *testing.T) {
	ctx := context.Background()

	session := mustNewSession(t, entity.AuthorizeRequestArgs{
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid",
	})
	sessionID := string(session.ID)

	newMod := func(seedSession bool) *usecase.Registry {
		mc := newMockCache()
		if seedSession {
			mc.items[fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID)] = session
		}
		mod := usecase.NewRegistry()
		mod.Register(GetSignInQuery{}, NewGetSignInUseCase(define.Dependencies{Cache: mc}))
		return mod
	}

	t.Run("returns session csrf token", func(t *testing.T) {
		result, err := newMod(true).Dispatch(ctx, &GetSignInQuery{SessionID: sessionID})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		res, ok := result.(*define.GetSignInResponse)
		if !ok {
			t.Fatalf("expected *define.GetSignInResponse, got %T", result)
		}
		if res.CSRFToken != session.CSRFToken {
			t.Errorf("CSRFToken = %q, want %q", res.CSRFToken, session.CSRFToken)
		}
		if res.HTMLPage() != define.HTMLPageSignIn {
			t.Errorf("HTMLPage() = %q, want %q", res.HTMLPage(), define.HTMLPageSignIn)
		}
		data := res.HTMLData()
		if data[define.HTMLKeyTitle] != define.HTMLTitleSignIn {
			t.Errorf("HTMLData[title] = %v, want %q", data[define.HTMLKeyTitle], define.HTMLTitleSignIn)
		}
		if data[define.HTMLKeyCsrfToken] != session.CSRFToken {
			t.Errorf("HTMLData[csrf_token] = %v, want %q", data[define.HTMLKeyCsrfToken], session.CSRFToken)
		}
	})

	t.Run("session not found — invalid session error", func(t *testing.T) {
		_, err := newMod(false).Dispatch(ctx, &GetSignInQuery{SessionID: sessionID})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
		}
	})

	t.Run("corrupted cached session — invalid session error", func(t *testing.T) {
		mc := newMockCache()
		mc.items[fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID)] = "corrupted"
		mod := usecase.NewRegistry()
		mod.Register(GetSignInQuery{}, NewGetSignInUseCase(define.Dependencies{Cache: mc}))
		_, err := mod.Dispatch(ctx, &GetSignInQuery{SessionID: sessionID})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
		}
	})

	t.Run("missing session_id — validation error", func(t *testing.T) {
		_, err := newMod(false).Dispatch(ctx, &GetSignInQuery{})
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.InvalidArguments {
			t.Fatalf("want err_code %d, got %v", autherrors.InvalidArguments, err)
		}
	})
}
