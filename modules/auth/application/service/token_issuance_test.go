package service

import (
	"errors"
	"testing"

	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

type mockJwtService struct {
	accessToken      string
	refreshToken     string
	idToken          string
	accessErr        error
	refreshErr       error
	idTokenErr       error
	genIDTokenCalled bool
	// captured arguments
	capturedGrantID        string
	capturedIDTokenGrantID string
}

func (m *mockJwtService) GenAccessToken(_, _, grantID string, _ int) (string, error) {
	m.capturedGrantID = grantID
	return m.accessToken, m.accessErr
}

func (m *mockJwtService) GenRefreshToken(_ string) (string, error) {
	return m.refreshToken, m.refreshErr
}

func (m *mockJwtService) GenIDToken(args port.IDTokenArgs) (string, error) {
	m.genIDTokenCalled = true
	m.capturedIDTokenGrantID = args.GrantID
	return m.idToken, m.idTokenErr
}

func TestTokenIssuanceService_IssueTokens(t *testing.T) {
	user := &entity.User{ID: "user-123", Email: "test@example.com"}
	req := IssueTokensArgs{
		User:       user,
		ClientID:   "client-1",
		Nonce:      "nonce-1",
		Scope:      entity.MustParseScope("openid profile"),
		ExpireSecs: 3600,
	}

	t.Run("success", func(t *testing.T) {
		jwtSvc := &mockJwtService{
			accessToken:  "at-123",
			refreshToken: "rt-123",
			idToken:      "it-123",
		}
		svc := NewTokenIssuanceService(jwtSvc)

		resp, err := svc.IssueTokens(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if resp.AccessToken != "at-123" {
			t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "at-123")
		}
		if resp.RefreshToken != "rt-123" {
			t.Errorf("RefreshToken = %q, want %q", resp.RefreshToken, "rt-123")
		}
		if resp.IDToken != "it-123" {
			t.Errorf("IDToken = %q, want %q", resp.IDToken, "it-123")
		}
		if resp.Scope.String() != "openid profile" {
			t.Errorf("Scope = %q, want %q", resp.Scope.String(), "openid profile")
		}
	})

	t.Run("genAccessToken fails", func(t *testing.T) {
		svc := NewTokenIssuanceService(&mockJwtService{accessErr: errors.New("jwt error")})

		resp, err := svc.IssueTokens(req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if resp != nil {
			t.Fatalf("expected nil response, got %+v", resp)
		}
	})

	t.Run("genRefreshToken fails", func(t *testing.T) {
		svc := NewTokenIssuanceService(&mockJwtService{refreshErr: errors.New("jwt error")})

		resp, err := svc.IssueTokens(req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if resp != nil {
			t.Fatalf("expected nil response, got %+v", resp)
		}
	})

	t.Run("genIDToken fails", func(t *testing.T) {
		svc := NewTokenIssuanceService(&mockJwtService{idTokenErr: errors.New("jwt error")})

		resp, err := svc.IssueTokens(req)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if resp != nil {
			t.Fatalf("expected nil response, got %+v", resp)
		}
	})

	t.Run("scope includes openid — id_token issued", func(t *testing.T) {
		jwtSvc := &mockJwtService{
			accessToken:  "at",
			refreshToken: "rt",
			idToken:      "it",
		}
		svc := NewTokenIssuanceService(jwtSvc)
		resp, err := svc.IssueTokens(IssueTokensArgs{
			User:       user,
			ClientID:   "client-1",
			Scope:      entity.MustParseScope("openid"),
			ExpireSecs: 3600,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.IDToken != "it" {
			t.Errorf("IDToken = %q, want %q", resp.IDToken, "it")
		}
		if !jwtSvc.genIDTokenCalled {
			t.Error("GenIDToken should have been called when scope contains openid")
		}
	})

	t.Run("scope without openid — id_token skipped", func(t *testing.T) {
		jwtSvc := &mockJwtService{
			accessToken:  "at",
			refreshToken: "rt",
		}
		svc := NewTokenIssuanceService(jwtSvc)
		resp, err := svc.IssueTokens(IssueTokensArgs{
			User:       user,
			ClientID:   "client-1",
			Scope:      entity.MustParseScope("email profile"),
			ExpireSecs: 3600,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.IDToken != "" {
			t.Errorf("IDToken = %q, want empty", resp.IDToken)
		}
		if jwtSvc.genIDTokenCalled {
			t.Error("GenIDToken should not have been called when scope lacks openid")
		}
	})

	t.Run("ExistingGrantID propagates to GenAccessToken, IDTokenArgs, and IssuedTokens", func(t *testing.T) {
		jwtSvc := &mockJwtService{
			accessToken:  "at",
			refreshToken: "rt",
			idToken:      "it",
		}
		svc := NewTokenIssuanceService(jwtSvc)
		resp, err := svc.IssueTokens(IssueTokensArgs{
			User:            user,
			ClientID:        "client-1",
			Scope:           entity.MustParseScope("openid"),
			ExpireSecs:      3600,
			ExistingGrantID: "existing-grant-1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if jwtSvc.capturedGrantID != "existing-grant-1" {
			t.Errorf("GenAccessToken received grantID = %q, want existing-grant-1", jwtSvc.capturedGrantID)
		}
		if jwtSvc.capturedIDTokenGrantID != "existing-grant-1" {
			t.Errorf("GenIDToken received GrantID = %q, want existing-grant-1", jwtSvc.capturedIDTokenGrantID)
		}
		if string(resp.GrantID) != "existing-grant-1" {
			t.Errorf("IssuedTokens.GrantID = %q, want existing-grant-1", resp.GrantID)
		}
	})

	t.Run("empty ExistingGrantID mints a fresh non-empty grant used consistently", func(t *testing.T) {
		jwtSvc := &mockJwtService{
			accessToken:  "at",
			refreshToken: "rt",
			idToken:      "it",
		}
		svc := NewTokenIssuanceService(jwtSvc)
		resp, err := svc.IssueTokens(IssueTokensArgs{
			User:       user,
			ClientID:   "client-1",
			Scope:      entity.MustParseScope("openid"),
			ExpireSecs: 3600,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if jwtSvc.capturedGrantID == "" {
			t.Error("GenAccessToken should receive a non-empty minted grantID")
		}
		if jwtSvc.capturedIDTokenGrantID != jwtSvc.capturedGrantID {
			t.Errorf("GenIDToken GrantID = %q, want same as GenAccessToken grantID = %q",
				jwtSvc.capturedIDTokenGrantID, jwtSvc.capturedGrantID)
		}
		if string(resp.GrantID) != jwtSvc.capturedGrantID {
			t.Errorf("IssuedTokens.GrantID = %q, want same as minted grantID = %q",
				resp.GrantID, jwtSvc.capturedGrantID)
		}
	})
}
