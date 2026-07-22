package command

import (
	"context"
	"fmt"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func mustNewSession(t *testing.T, args entity.AuthorizeRequestArgs) *entity.AuthorizeRequest {
	t.Helper()
	s, err := entity.NewAuthorizeRequest(args)
	if err != nil {
		t.Fatalf("setup: NewAuthorizeRequest: %v", err)
	}
	return s
}

func TestCreateAuthCodeUseCase(t *testing.T) {
	user := newTestUserWithValidPassword()
	userRepo := newMockRepo(user)

	session := mustNewSession(t, entity.AuthorizeRequestArgs{
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid email",
		State:       new("state-xyz"),
		Nonce:       new("nonce-abc"),
	})
	sessionID := string(session.ID)

	base := &CreateAuthCodeCommand{
		Email:     "test@example.com",
		Password:  "Password1!",
		CSRFToken: session.CSRFToken,
		SessionID: sessionID,
	}

	newUC := func(seedSession bool) (*CreateAuthCodeUseCase, *mockCache) {
		c := newMockCache()
		if seedSession {
			c.seed(fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID), session)
		}
		return &CreateAuthCodeUseCase{userRepo: userRepo, cache: c}, c
	}

	tests := []struct {
		name        string
		modify      func(c *CreateAuthCodeCommand)
		seedSession bool
		wantErrCode coreerror.ErrCode
		check       func(t *testing.T, cache *mockCache, res *define.CreateAuthCodeResponse)
	}{
		{
			name:        "valid credentials — returns redirect URL with code and state",
			modify:      func(c *CreateAuthCodeCommand) {},
			seedSession: true,
			check: func(t *testing.T, cache *mockCache, res *define.CreateAuthCodeResponse) {
				cookies := res.Cookies()
				if len(cookies) != 1 || cookies[0].Name != define.CookieAuthorizeRequest || cookies[0].MaxAge != -1 {
					t.Errorf("Cookies() = %+v, want single auth_session clear cookie (MaxAge=-1)", cookies)
				}

				redirectURL := res.URL()
				if !strings.HasPrefix(redirectURL, session.RedirectURI+"?code=") {
					t.Errorf("redirectURL = %q, want prefix %q?code=", redirectURL, session.RedirectURI)
				}
				if !strings.Contains(redirectURL, "state=state-xyz") {
					t.Errorf("redirectURL missing state param: %q", redirectURL)
				}

				// parse code and verify stored auth code fields
				codeStart := strings.Index(redirectURL, "code=") + len("code=")
				codeEnd := strings.Index(redirectURL[codeStart:], "&")
				var code string
				if codeEnd == -1 {
					code = redirectURL[codeStart:]
				} else {
					code = redirectURL[codeStart : codeStart+codeEnd]
				}
				raw, ok := cache.items[fmt.Sprintf(define.AuthCodeCacheKey, code)]
				if !ok {
					t.Fatal("auth code not found in cache")
				}
				ac := raw.(*entity.AuthCode)
				if ac.UserID != user.ID {
					t.Errorf("AuthCode.UserID = %q, want %q", ac.UserID, user.ID)
				}
				if ac.ClientID == nil || *ac.ClientID != session.ClientID {
					t.Errorf("AuthCode.ClientID = %v, want %v", ac.ClientID, session.ClientID)
				}
				if ac.RedirectURI != session.RedirectURI {
					t.Errorf("AuthCode.RedirectURI = %q, want %q", ac.RedirectURI, session.RedirectURI)
				}
				if ac.Scope.String() != session.Scope.String() {
					t.Errorf("AuthCode.Scope = %q, want %q", ac.Scope.String(), session.Scope.String())
				}
				if ac.Nonce == nil || *ac.Nonce != "nonce-abc" {
					t.Errorf("AuthCode.Nonce = %v, want nonce-abc", ac.Nonce)
				}
			},
		},
		{
			name:        "wrong password — error, session preserved for retry",
			modify:      func(c *CreateAuthCodeCommand) { c.Password = "wrong" },
			seedSession: true,
			wantErrCode: autherrors.InvalidEmailOrPassword,
		},
		{
			name:        "unknown email — error",
			modify:      func(c *CreateAuthCodeCommand) { c.Email = "nobody@example.com" },
			seedSession: true,
			wantErrCode: autherrors.InvalidEmailOrPassword,
		},
		{
			name:        "no session cookie — error",
			modify:      func(c *CreateAuthCodeCommand) { c.SessionID = "" },
			seedSession: false,
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "session not in cache (expired) — error",
			modify:      func(c *CreateAuthCodeCommand) {},
			seedSession: false,
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "CSRF mismatch — error",
			modify:      func(c *CreateAuthCodeCommand) { c.CSRFToken = "wrong-csrf" },
			seedSession: true,
			wantErrCode: autherrors.InvalidArguments,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uc, cache := newUC(tc.seedSession)
			cmd := *base
			tc.modify(&cmd)
			result, err := uc.Execute(context.Background(), &cmd)

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
			if tc.check != nil {
				res, ok := result.(*define.CreateAuthCodeResponse)
				if !ok {
					t.Fatalf("expected *define.CreateAuthCodeResponse, got %T", result)
				}
				tc.check(t, cache, res)
			}
		})
	}
}

func TestCreateAuthCodeUseCase_Validation(t *testing.T) {
	ctx := context.Background()
	mod := usecase.NewRegistry()
	mod.Register(CreateAuthCodeCommand{}, NewCreateAuthCodeUseCase(define.Dependencies{
		UserRepo: newMockRepo(newTestUser()),
		Cache:    newMockCache(),
	}))

	cases := []struct {
		name string
		cmd  *CreateAuthCodeCommand
	}{
		{"missing email", &CreateAuthCodeCommand{Password: "Password1!", CSRFToken: "tok", SessionID: "sess-id"}},
		{"missing password", &CreateAuthCodeCommand{Email: "a@b.com", CSRFToken: "tok", SessionID: "sess-id"}},
		{"missing csrf_token", &CreateAuthCodeCommand{Email: "a@b.com", Password: "Password1!", SessionID: "sess-id"}},
		{"missing session_id", &CreateAuthCodeCommand{Email: "a@b.com", Password: "Password1!", CSRFToken: "tok"}},
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
}

func TestCreateAuthCodeUseCase_PKCEPropagation(t *testing.T) {
	user := newTestUserWithValidPassword()
	userRepo := newMockRepo(user)

	session := mustNewSession(t, entity.AuthorizeRequestArgs{
		ClientID:            "client-123",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "openid",
		CodeChallenge:       new("Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg"),
		CodeChallengeMethod: new("S256"),
	})
	sessionID := string(session.ID)

	c := newMockCache()
	c.seed(fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID), session)
	uc := &CreateAuthCodeUseCase{userRepo: userRepo, cache: c}

	result, err := uc.Execute(context.Background(), &CreateAuthCodeCommand{
		Email:     "test@example.com",
		Password:  "Password1!",
		CSRFToken: session.CSRFToken,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	redirectURL := result.(*define.CreateAuthCodeResponse).URL()
	codeStart := strings.Index(redirectURL, "code=") + len("code=")
	code := redirectURL[codeStart:]

	raw, ok := c.items[fmt.Sprintf(define.AuthCodeCacheKey, code)]
	if !ok {
		t.Fatal("auth code not found in cache")
	}
	ac := raw.(*entity.AuthCode)
	if ac.CodeChallenge == nil || *ac.CodeChallenge != "Ds3NpaREu9I2EYq6l0l3ZkFyv_Gt5O4EpGD6cZlY0Kg" {
		t.Errorf("CodeChallenge not propagated: %v", ac.CodeChallenge)
	}
	if ac.CodeChallengeMethod == nil || *ac.CodeChallengeMethod != "S256" {
		t.Errorf("CodeChallengeMethod not propagated: %v", ac.CodeChallengeMethod)
	}
}

func TestCreateAuthCodeUseCase_SessionConsumedOnSuccess(t *testing.T) {
	user := newTestUserWithValidPassword()
	userRepo := newMockRepo(user)

	session := mustNewSession(t, entity.AuthorizeRequestArgs{
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid",
	})
	sessionID := string(session.ID)

	c := newMockCache().seed(fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID), session)
	uc := &CreateAuthCodeUseCase{userRepo: userRepo, cache: c}

	cmd := &CreateAuthCodeCommand{
		Email:     "test@example.com",
		Password:  "Password1!",
		CSRFToken: session.CSRFToken,
		SessionID: sessionID,
	}

	if _, err := uc.Execute(context.Background(), cmd); err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// session consumed — second call must fail
	if _, err := uc.Execute(context.Background(), cmd); err == nil {
		t.Fatal("expected error on session replay, got nil")
	}
}

func TestCreateAuthCodeUseCase_LocksOutAfterMaxFailedAttempts(t *testing.T) {
	user := newTestUser()
	userRepo := newMockRepo(user)

	session := mustNewSession(t, entity.AuthorizeRequestArgs{
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid",
	})
	sessionID := string(session.ID)
	sessionKey := fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID)

	c := newMockCache().seed(sessionKey, session)
	uc := &CreateAuthCodeUseCase{userRepo: userRepo, cache: c}

	bad := &CreateAuthCodeCommand{
		Email:     "test@example.com",
		Password:  "wrong",
		CSRFToken: session.CSRFToken,
		SessionID: sessionID,
	}

	// first two attempts keep session alive with incrementing FailedAttempts
	for i := 1; i < 3; i++ {
		if _, err := uc.Execute(context.Background(), bad); err == nil {
			t.Fatalf("attempt %d: expected error, got nil", i)
		}
		var s entity.AuthorizeRequest
		if ok := c.Get(context.Background(), sessionKey, &s); !ok {
			t.Fatalf("attempt %d: session should still be in cache", i)
		}
		if s.FailedAttempts != i {
			t.Errorf("attempt %d: FailedAttempts = %d, want %d", i, s.FailedAttempts, i)
		}
	}

	// third attempt triggers lockout
	_, err := uc.Execute(context.Background(), bad)
	if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != autherrors.MaxLoginAttemptsExceeded {
		t.Errorf("want MaxLoginAttemptsExceeded error, got %v", err)
	}
	var s entity.AuthorizeRequest
	if c.Get(context.Background(), sessionKey, &s) {
		t.Error("session should be deleted after lockout")
	}
}

func TestCreateAuthCodeUseCase_WrongPasswordPreservesSession(t *testing.T) {
	user := newTestUserWithValidPassword()
	userRepo := newMockRepo(user)

	session := mustNewSession(t, entity.AuthorizeRequestArgs{
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid",
	})
	sessionID := string(session.ID)

	c := newMockCache().seed(fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID), session)
	uc := &CreateAuthCodeUseCase{userRepo: userRepo, cache: c}

	bad := &CreateAuthCodeCommand{
		Email:     "test@example.com",
		Password:  "wrong",
		CSRFToken: session.CSRFToken,
		SessionID: sessionID,
	}
	if _, err := uc.Execute(context.Background(), bad); err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}

	// session must still be present for retry
	good := &CreateAuthCodeCommand{
		Email:     "test@example.com",
		Password:  "Password1!",
		CSRFToken: session.CSRFToken,
		SessionID: sessionID,
	}
	if _, err := uc.Execute(context.Background(), good); err != nil {
		t.Fatalf("retry with correct password failed: %v", err)
	}
}

func TestCreateAuthCode_AccountLockout(t *testing.T) {
	ctx := context.Background()

	// Each attempt uses a fresh /authorize session, so the per-session
	// counter never trips — only the account-level lockout is exercised.
	attempt := func(t *testing.T, userRepo *mockUserRepo, password string) error {
		t.Helper()
		session := mustNewSession(t, entity.AuthorizeRequestArgs{
			ClientID:    "client-123",
			RedirectURI: "https://app.example.com/callback",
			Scope:       "openid",
		})
		cache := newMockCache().seed(fmt.Sprintf(define.AuthorizeRequestCacheKey, string(session.ID)), session)
		uc := &CreateAuthCodeUseCase{userRepo: userRepo, cache: cache}
		_, err := uc.Execute(ctx, &CreateAuthCodeCommand{
			Email:     "test@example.com",
			Password:  password,
			CSRFToken: session.CSRFToken,
			SessionID: string(session.ID),
		})
		return err
	}

	wantCode := func(t *testing.T, err error, want coreerror.ErrCode) {
		t.Helper()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != want {
			t.Fatalf("got err %v, want err_code %d", err, want)
		}
	}

	t.Run("failures across different sessions lock the account", func(t *testing.T) {
		user := newTestUser()
		userRepo := newMockRepo(user)

		for i := 0; i < entity.MaxFailedLoginAttempts; i++ {
			wantCode(t, attempt(t, userRepo, "Wrong1!pass"), autherrors.InvalidEmailOrPassword)
		}
		if user.LockedUntil == nil {
			t.Fatal("account must be locked after MaxFailedLoginAttempts failures")
		}

		// Correct password on a locked account: same generic error (no oracle).
		wantCode(t, attempt(t, userRepo, "Password1!"), autherrors.InvalidEmailOrPassword)
	})

	t.Run("successful login resets the counter", func(t *testing.T) {
		user := newTestUserWithValidPassword()
		userRepo := newMockRepo(user)

		for i := 0; i < entity.MaxFailedLoginAttempts-1; i++ {
			wantCode(t, attempt(t, userRepo, "Wrong1!pass"), autherrors.InvalidEmailOrPassword)
		}
		if err := attempt(t, userRepo, "Password1!"); err != nil {
			t.Fatalf("login below threshold must succeed, got %v", err)
		}
		if user.FailedLoginAttempts != 0 || user.LockedUntil != nil {
			t.Errorf("successful login must reset failures, got attempts=%d locked=%v", user.FailedLoginAttempts, user.LockedUntil)
		}

		// One more failure after the reset must not lock.
		wantCode(t, attempt(t, userRepo, "Wrong1!pass"), autherrors.InvalidEmailOrPassword)
		if user.LockedUntil != nil {
			t.Error("a single failure after reset must not lock the account")
		}
	})
}

func TestCreateAuthCode_RehashOnLogin(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("Password1!"), 10)
	if err != nil {
		t.Fatalf("setup: GenerateFromPassword: %v", err)
	}
	user := newTestUser()
	user.Password = string(hash)
	userRepo := newMockRepo(user)

	session := mustNewSession(t, entity.AuthorizeRequestArgs{
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
		Scope:       "openid",
	})
	sessionID := string(session.ID)
	c := newMockCache().seed(fmt.Sprintf(define.AuthorizeRequestCacheKey, sessionID), session)
	uc := &CreateAuthCodeUseCase{userRepo: userRepo, cache: c}

	if _, err := uc.Execute(context.Background(), &CreateAuthCodeCommand{
		Email:     "test@example.com",
		Password:  "Password1!",
		CSRFToken: session.CSRFToken,
		SessionID: sessionID,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cost, err := bcrypt.Cost([]byte(user.Password))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != 12 {
		t.Errorf("saved hash cost = %d, want 12", cost)
	}
}
