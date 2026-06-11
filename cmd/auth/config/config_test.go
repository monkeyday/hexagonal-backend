package config

import (
	"slices"
	"testing"
)

func TestParseClientConfig(t *testing.T) {
	t.Run("no client and no DEV_SEED — panics (fail closed)", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "")
		t.Setenv("DEV_SEED", "")
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic when no client is configured")
			}
		}()
		parseClientConfig()
	})

	t.Run("no client with DEV_SEED=true — dev default client", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "")
		t.Setenv("DEV_SEED", "true")
		got := parseClientConfig()
		if got.ID != defaultClientID {
			t.Errorf("ID = %q, want %q", got.ID, defaultClientID)
		}
		if got.AuthMethod != defaultClientAuthMethod {
			t.Errorf("AuthMethod = %q, want %q", got.AuthMethod, defaultClientAuthMethod)
		}
		if !slices.Equal(got.RedirectURIs, defaultClientRedirectURIs) {
			t.Errorf("RedirectURIs = %v, want %v", got.RedirectURIs, defaultClientRedirectURIs)
		}
	})

	t.Run("explicit client — parsed from env", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "acme-web")
		t.Setenv("OAUTH_CLIENT_AUTH_METHOD", "client_secret_post")
		t.Setenv("OAUTH_CLIENT_SECRET", "s3cret")
		t.Setenv("OAUTH_CLIENT_REDIRECT_URIS", "https://acme.example.com/cb,https://acme.example.com/cb2")
		t.Setenv("OAUTH_CLIENT_ALLOWED_GRANTS", "authorization_code,refresh_token")
		t.Setenv("DEV_SEED", "")
		got := parseClientConfig()
		if got.ID != "acme-web" || got.AuthMethod != "client_secret_post" || got.Secret != "s3cret" {
			t.Errorf("unexpected client config: %+v", got)
		}
		if !slices.Equal(got.RedirectURIs, []string{"https://acme.example.com/cb", "https://acme.example.com/cb2"}) {
			t.Errorf("RedirectURIs = %v", got.RedirectURIs)
		}
		if !slices.Equal(got.AllowedGrants, []string{"authorization_code", "refresh_token"}) {
			t.Errorf("AllowedGrants = %v", got.AllowedGrants)
		}
	})

	t.Run("explicit client without optional vars — defaults applied", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "acme-web")
		t.Setenv("OAUTH_CLIENT_AUTH_METHOD", "")
		t.Setenv("OAUTH_CLIENT_SECRET", "")
		t.Setenv("OAUTH_CLIENT_REDIRECT_URIS", "https://acme.example.com/cb")
		t.Setenv("OAUTH_CLIENT_ALLOWED_GRANTS", "")
		got := parseClientConfig()
		if got.AuthMethod != defaultClientAuthMethod {
			t.Errorf("AuthMethod = %q, want default %q", got.AuthMethod, defaultClientAuthMethod)
		}
		if !slices.Equal(got.AllowedGrants, defaultClientAllowedGrants) {
			t.Errorf("AllowedGrants = %v, want defaults", got.AllowedGrants)
		}
	})
}
