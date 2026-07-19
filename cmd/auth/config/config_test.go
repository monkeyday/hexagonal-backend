package config

import (
	"slices"
	"testing"

	"sc/core/validator"
	coreweb "sc/core/web"
	infrajwt "sc/infrastructure/jwt"
	mongorepo "sc/infrastructure/repository/mongo"
	infrasmtp "sc/infrastructure/smtp"
)

// validBaseSettings returns a Settings that passes validation except for the
// repository discriminator, so repo cases can be asserted in isolation.
func validBaseSettings() *Settings {
	return &Settings{
		Server: coreweb.Config{Port: "8080"},
		JWT: infrajwt.Config{
			PrivateKeyPath: "private.pem",
			PublicKeyPath:  "public.pem",
			Issuer:         "https://issuer.example.com",
			Kid:            "kid-1",
		},
	}
}

func completeMongo() *mongorepo.Config {
	return &mongorepo.Config{Host: "h", Username: "u", Password: "p", AuthSource: "admin", Database: "db"}
}

func completeFileRepo() *FileRepositoryConfig {
	return &FileRepositoryConfig{Dir: "/data", UserFileName: "users.json", RefreshTokenFileName: "refresh_tokens.json"}
}

func TestSettingsRepositoryValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Settings)
		wantErr bool
	}{
		{"mongo selected, complete", func(s *Settings) { s.RepositoryType = "mongo"; s.Mongo = completeMongo() }, false},
		{"mongo selected, nil config", func(s *Settings) { s.RepositoryType = "mongo" }, true},
		{"mongo selected, missing field", func(s *Settings) {
			s.RepositoryType = "mongo"
			m := completeMongo()
			m.Username = ""
			s.Mongo = m
		}, true},
		{"file selected, complete", func(s *Settings) { s.RepositoryType = "file"; s.FileRepository = completeFileRepo() }, false},
		{"file selected, nil config", func(s *Settings) { s.RepositoryType = "file" }, true},
		{"empty type, file config present (empty == file)", func(s *Settings) { s.FileRepository = completeFileRepo() }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validBaseSettings()
			tt.mutate(s)
			err := validator.ValidateStruct(s)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateStruct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func completeSMTP() *infrasmtp.Config {
	return &infrasmtp.Config{Host: "smtp.example.com", Port: "587", From: "no-reply@example.com"}
}

func TestSettingsSMTPValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Settings)
		wantErr bool
	}{
		{"smtp disabled, no base url", func(s *Settings) {}, false},
		{"smtp set, complete with base url", func(s *Settings) { s.SMTP = completeSMTP(); s.AppBaseURL = "https://app.example.com" }, false},
		{"smtp set, missing base url", func(s *Settings) { s.SMTP = completeSMTP() }, true},
		{"smtp set, incomplete config", func(s *Settings) {
			m := completeSMTP()
			m.From = ""
			s.SMTP = m
			s.AppBaseURL = "https://app.example.com"
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validBaseSettings()
			tt.mutate(s)
			err := validator.ValidateStruct(s)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateStruct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseClientConfig(t *testing.T) {
	t.Run("no client and no DEV_SEED — panics (fail closed)", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "")
		t.Setenv("DEV_SEED", "")
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic when no client is configured")
			}
		}()
		parsePrimaryClientConfig()
	})

	t.Run("no client with DEV_SEED=true — dev default client", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "")
		t.Setenv("DEV_SEED", "true")
		got := parsePrimaryClientConfig()
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
		got := parsePrimaryClientConfig()
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
		got := parsePrimaryClientConfig()
		if got.AuthMethod != defaultClientAuthMethod {
			t.Errorf("AuthMethod = %q, want default %q", got.AuthMethod, defaultClientAuthMethod)
		}
		if !slices.Equal(got.AllowedGrants, defaultClientAllowedGrants) {
			t.Errorf("AllowedGrants = %v, want defaults", got.AllowedGrants)
		}
	})
}

func TestParseClientConfigs(t *testing.T) {
	t.Run("primary only — single entry", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "my_client")
		t.Setenv("OAUTH_CLIENT_AUTH_METHOD", "none")
		got := parseClientConfigs()
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if got[0].ID != "my_client" || got[0].AuthMethod != "none" {
			t.Errorf("unexpected primary client: %+v", got[0])
		}
	})

	t.Run("primary plus indexed clients", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "my_client")
		t.Setenv("OAUTH_CLIENT_AUTH_METHOD", "none")
		t.Setenv("OAUTH_CLIENT_2_ID", "supabase")
		t.Setenv("OAUTH_CLIENT_2_AUTH_METHOD", "client_secret_post")
		t.Setenv("OAUTH_CLIENT_2_SECRET", "s3cret")
		t.Setenv("OAUTH_CLIENT_2_REDIRECT_URIS", "https://app/callback")
		got := parseClientConfigs()
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[1].ID != "supabase" || got[1].AuthMethod != "client_secret_post" || got[1].Secret != "s3cret" {
			t.Errorf("unexpected indexed client: %+v", got[1])
		}
		if !slices.Equal(got[1].RedirectURIs, []string{"https://app/callback"}) {
			t.Errorf("RedirectURIs = %v", got[1].RedirectURIs)
		}
	})

	t.Run("stops at first gap — CLIENT_3 ignored without CLIENT_2", func(t *testing.T) {
		t.Setenv("OAUTH_CLIENT_ID", "my_client")
		t.Setenv("OAUTH_CLIENT_3_ID", "orphan")
		got := parseClientConfigs()
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1 (CLIENT_3 must not be reached past the CLIENT_2 gap)", len(got))
		}
	})
}
