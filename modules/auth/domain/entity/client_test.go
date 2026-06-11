package entity

import (
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	validURIs := []string{"https://app.example.com/callback"}
	validGrants := []GrantType{GrantAuthorizationCode, GrantRefreshToken}

	tests := []struct {
		name    string
		args    ClientArgs
		wantErr string
		check   func(t *testing.T, c *Client)
	}{
		{
			name: "public client — no secret hash, default tenant",
			args: ClientArgs{ID: "client-123", AuthMethod: ClientAuthNone, RedirectURIs: validURIs, AllowedGrants: validGrants},
			check: func(t *testing.T, c *Client) {
				if c.SecretHash != nil {
					t.Error("expected nil SecretHash for public client")
				}
				if c.TenantID != DefaultTenantID {
					t.Errorf("TenantID = %q, want %q", c.TenantID, DefaultTenantID)
				}
				if !c.IsPublic() {
					t.Error("IsPublic() = false, want true")
				}
			},
		},
		{
			name: "confidential client — secret hashed and verifiable",
			args: ClientArgs{ID: "client-123", AuthMethod: ClientAuthSecretBasic, Secret: "s3cret-value", RedirectURIs: validURIs, AllowedGrants: validGrants},
			check: func(t *testing.T, c *Client) {
				if c.SecretHash == nil {
					t.Fatal("expected SecretHash for confidential client")
				}
				if *c.SecretHash == "s3cret-value" {
					t.Error("secret stored in plaintext")
				}
				if err := c.VerifySecret("s3cret-value"); err != nil {
					t.Errorf("VerifySecret(correct) = %v, want nil", err)
				}
				if err := c.VerifySecret("wrong"); err == nil {
					t.Error("VerifySecret(wrong) = nil, want error")
				}
				if c.IsPublic() {
					t.Error("IsPublic() = true, want false")
				}
			},
		},
		{
			name: "explicit tenant is kept",
			args: ClientArgs{ID: "client-123", TenantID: "acme", AuthMethod: ClientAuthNone, RedirectURIs: validURIs, AllowedGrants: validGrants},
			check: func(t *testing.T, c *Client) {
				if c.TenantID != "acme" {
					t.Errorf("TenantID = %q, want acme", c.TenantID)
				}
			},
		},
		{
			name: "redirect URIs are normalized",
			args: ClientArgs{ID: "client-123", AuthMethod: ClientAuthNone, RedirectURIs: []string{"HTTPS://app.example.com/callback"}, AllowedGrants: validGrants},
			check: func(t *testing.T, c *Client) {
				if c.RedirectURIs[0] != "https://app.example.com/callback" {
					t.Errorf("RedirectURIs[0] = %q, want normalized scheme", c.RedirectURIs[0])
				}
				if !c.AllowsRedirectURI("HTTPS://app.example.com/callback") {
					t.Error("AllowsRedirectURI should match in normalized space")
				}
				if c.AllowsRedirectURI("https://evil.com/cb") {
					t.Error("AllowsRedirectURI accepted an unregistered URI")
				}
			},
		},
		{
			name:    "empty id rejected",
			args:    ClientArgs{AuthMethod: ClientAuthNone, RedirectURIs: validURIs, AllowedGrants: validGrants},
			wantErr: "client_id",
		},
		{
			name:    "no redirect URIs rejected",
			args:    ClientArgs{ID: "client-123", AuthMethod: ClientAuthNone, AllowedGrants: validGrants},
			wantErr: "redirect URI",
		},
		{
			name:    "no grants rejected",
			args:    ClientArgs{ID: "client-123", AuthMethod: ClientAuthNone, RedirectURIs: validURIs},
			wantErr: "grant type",
		},
		{
			name:    "public client with secret rejected",
			args:    ClientArgs{ID: "client-123", AuthMethod: ClientAuthNone, Secret: "oops", RedirectURIs: validURIs, AllowedGrants: validGrants},
			wantErr: "must not have a secret",
		},
		{
			name:    "confidential client without secret rejected",
			args:    ClientArgs{ID: "client-123", AuthMethod: ClientAuthSecretPost, RedirectURIs: validURIs, AllowedGrants: validGrants},
			wantErr: "requires a secret",
		},
		{
			name:    "unknown auth method rejected",
			args:    ClientArgs{ID: "client-123", AuthMethod: "client_secret_jwt", RedirectURIs: validURIs, AllowedGrants: validGrants},
			wantErr: "token_endpoint_auth_method",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, c)
			}
		})
	}
}

func TestClient_AllowsGrant(t *testing.T) {
	c, err := NewClient(ClientArgs{
		ID:            "client-123",
		AuthMethod:    ClientAuthNone,
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []GrantType{GrantAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if !c.AllowsGrant(GrantAuthorizationCode) {
		t.Error("AllowsGrant(authorization_code) = false, want true")
	}
	if c.AllowsGrant(GrantClientCredentials) {
		t.Error("AllowsGrant(client_credentials) = true, want false")
	}
}

func TestParseClientAuthMethod(t *testing.T) {
	tests := []struct {
		raw     string
		want    ClientAuthMethod
		wantErr bool
	}{
		{raw: "none", want: ClientAuthNone},
		{raw: "client_secret_basic", want: ClientAuthSecretBasic},
		{raw: "client_secret_post", want: ClientAuthSecretPost},
		{raw: "client_secret_jwt", wantErr: true},
		{raw: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run("method "+tc.raw, func(t *testing.T) {
			got, err := ParseClientAuthMethod(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ParseClientAuthMethod(%q) = (%q, %v), want %q", tc.raw, got, err, tc.want)
			}
		})
	}
}

func TestParseGrantType(t *testing.T) {
	tests := []struct {
		raw     string
		want    GrantType
		wantErr bool
	}{
		{raw: "authorization_code", want: GrantAuthorizationCode},
		{raw: "refresh_token", want: GrantRefreshToken},
		{raw: "password", want: GrantPassword},
		{raw: "client_credentials", want: GrantClientCredentials},
		{raw: "implicit", wantErr: true},
		{raw: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run("grant "+tc.raw, func(t *testing.T) {
			got, err := ParseGrantType(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ParseGrantType(%q) = (%q, %v), want %q", tc.raw, got, err, tc.want)
			}
		})
	}
}
