package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"sc/core/validator"
	coreweb "sc/core/web"
	infracache "sc/infrastructure/cache"
	infrajwt "sc/infrastructure/jwt"
	mongorepo "sc/infrastructure/repository/mongo"
	infrasmtp "sc/infrastructure/smtp"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

const envFile = ".env"

type Settings struct {
	Server         coreweb.Config          `validate:"required"`
	JWT            infrajwt.Config         `validate:"required"`
	RepositoryType string                  `validate:"omitempty,oneof=file mongo"`
	FileRepository FileRepositoryConfig    `validate:"-"` // validated contextually when RepositoryType == "file"
	Mongo          mongorepo.Config        `validate:"-"` // validated contextually when RepositoryType == "mongo"
	Redis          infracache.RedisOptions // optional; used when REDIS_ADDR is set
	OAuth          OAuthConfig
	SMTP           infrasmtp.Config `validate:"-"` // validated contextually when SMTP_HOST is set
	AppBaseURL     string           // base URL for password-reset links
}

type FileRepositoryConfig struct {
	Dir                  string `validate:"required"`
	UserFileName         string `validate:"required"`
	RefreshTokenFileName string `validate:"required"`
}

type OAuthConfig struct {
	Client                      ClientConfig
	PostLogoutRedirectAllowlist []string
	ScopeAllowlist              []string
}

// ClientConfig declares the single registered OAuth client until a persistent
// client registry lands. Parsed into an entity.Client at composition time.
type ClientConfig struct {
	ID            string
	AuthMethod    string
	Secret        string
	RedirectURIs  []string
	AllowedGrants []string
}

var (
	once sync.Once
	cfg  *Settings
)

func Load(entryPath string) *Settings {
	once.Do(func() {
		envPath := envFilePath(entryPath)
		if err := godotenv.Load(envPath); err != nil {
			log.Err(err).Msg("Failed to load environment variables")
			panic("Error loading environment variables")
		}

		cfg = &Settings{
			Server: coreweb.Config{
				Port:         os.Getenv("PORT"),
				CorsOrigins:  parseCorsOrigins(os.Getenv("CORS_ORIGINS")),
				CookieSecure: os.Getenv("COOKIE_SECURE") == "true",
				MetricsAddr:  os.Getenv("METRICS_ADDR"),
			},
			JWT: infrajwt.Config{
				PrivateKeyPath: os.Getenv("PRIVATE_KEY_PATH"),
				PublicKeyPath:  os.Getenv("PUBLIC_KEY_PATH"),
				Issuer:         os.Getenv("JWT_ISSUER"),
				Kid:            os.Getenv("JWT_KID"),
			},
			RepositoryType: os.Getenv("REPOSITORY_USED"),
			FileRepository: FileRepositoryConfig{
				Dir:                  os.Getenv("FILE_DIR"),
				UserFileName:         os.Getenv("USER_FILE_PATH"),
				RefreshTokenFileName: "refresh_tokens.json",
			},
			Mongo: mongorepo.Config{
				Host:       os.Getenv("MONGO_HOST"),
				Username:   os.Getenv("MONGO_USER"),
				Password:   os.Getenv("MONGO_PASSWORD"),
				AuthSource: os.Getenv("MONGO_AUTH_SOURCE"),
				Database:   os.Getenv("MONGO_DATABASE"),
				Direct:     true,
			},
			Redis: infracache.RedisOptions{
				Addr:     os.Getenv("REDIS_ADDR"),
				Password: os.Getenv("REDIS_PASSWORD"),
				DB:       parseRedisDB(os.Getenv("REDIS_DB")),
			},
			OAuth: OAuthConfig{
				Client:                      parseClientConfig(),
				PostLogoutRedirectAllowlist: parseCommaSeparated(os.Getenv("OAUTH_POST_LOGOUT_REDIRECT_ALLOWLIST")),
				ScopeAllowlist:              parseScopeAllowlist(os.Getenv("OAUTH_SCOPE_ALLOWLIST")),
			},
			SMTP: infrasmtp.Config{
				Host: os.Getenv("SMTP_HOST"),
				Port: os.Getenv("SMTP_PORT"),
				From: os.Getenv("SMTP_FROM"),
			},
			AppBaseURL: os.Getenv("APP_BASE_URL"),
		}

		if err := validator.ValidateStruct(cfg); err != nil {
			log.Err(err).Msg("Failed to validate configuration")
			panic(err)
		}

		var repoErr error
		if cfg.RepositoryType == "mongo" {
			repoErr = validator.ValidateStruct(cfg.Mongo)
		} else {
			repoErr = validator.ValidateStruct(cfg.FileRepository)
		}
		if repoErr != nil {
			log.Err(repoErr).Msg("Failed to validate configuration")
			panic(repoErr)
		}

		if cfg.SMTP.Host != "" {
			if err := validator.ValidateStruct(cfg.SMTP); err != nil {
				log.Err(err).Msg("SMTP_HOST is set but SMTP configuration is incomplete")
				panic(err)
			}
			if cfg.AppBaseURL == "" {
				panic("APP_BASE_URL is required when SMTP_HOST is set")
			}
		}
	})

	return cfg
}

func parseRedisDB(raw string) int {
	if raw == "" {
		return 0
	}
	db, err := strconv.Atoi(raw)
	if err != nil || db < 0 {
		log.Error().Str("REDIS_DB", raw).Msg("invalid REDIS_DB value; must be a non-negative integer")
		panic("invalid REDIS_DB configuration")
	}
	return db
}

const (
	defaultClientID         = "client-123"
	defaultClientAuthMethod = "none"
)

var (
	defaultClientRedirectURIs = []string{"https://app.example.com/callback", "http://localhost:3000/callback"}
	// All supported grants until per-client grant enforcement lands (finding #1).
	defaultClientAllowedGrants = []string{"authorization_code", "refresh_token", "password", "client_credentials"}
)

func parseClientConfig() ClientConfig {
	id := os.Getenv("OAUTH_CLIENT_ID")
	if id == "" {
		// Fail closed: never serve /authorize for a fictitious default client.
		// Local development opts in to the seed client explicitly.
		if os.Getenv("DEV_SEED") != "true" {
			panic("no OAuth client configured: set OAUTH_CLIENT_ID (and related OAUTH_CLIENT_* vars), or DEV_SEED=true for local development")
		}
		log.Warn().Str("client_id", defaultClientID).Msg("DEV_SEED=true: using built-in development OAuth client; never enable in production")
		return ClientConfig{
			ID:            defaultClientID,
			AuthMethod:    defaultClientAuthMethod,
			RedirectURIs:  defaultClientRedirectURIs,
			AllowedGrants: defaultClientAllowedGrants,
		}
	}

	authMethod := os.Getenv("OAUTH_CLIENT_AUTH_METHOD")
	if authMethod == "" {
		authMethod = defaultClientAuthMethod
	}
	grants := parseCommaSeparated(os.Getenv("OAUTH_CLIENT_ALLOWED_GRANTS"))
	if len(grants) == 0 {
		grants = defaultClientAllowedGrants
	}

	return ClientConfig{
		ID:            id,
		AuthMethod:    authMethod,
		Secret:        os.Getenv("OAUTH_CLIENT_SECRET"),
		RedirectURIs:  parseCommaSeparated(os.Getenv("OAUTH_CLIENT_REDIRECT_URIS")),
		AllowedGrants: grants,
	}
}

func parseScopeAllowlist(raw string) []string {
	if raw == "" {
		return []string{"openid", "email", "profile", "phone"}
	}
	return parseCommaSeparated(raw)
}

func parseCommaSeparated(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseCorsOrigins(raw string) []string {
	if raw == "" {
		return []string{"*"}
	}
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			origins = append(origins, s)
		}
	}
	return origins
}

func envFilePath(entryPath string) string {
	if f := os.Getenv("ENV_PATH"); f != "" {
		return f
	}
	return filepath.Join(entryPath, envFile)
}
