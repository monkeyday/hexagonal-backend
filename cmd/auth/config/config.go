package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
	Server         coreweb.Config        `validate:"required"`
	JWT            infrajwt.Config       `validate:"required"`
	RepositoryType string                `validate:"omitempty,oneof=file mongo"`
	FileRepository *FileRepositoryConfig `validate:"required_if=RepositoryType file"`
	Mongo          *mongorepo.Config     `validate:"required_if=RepositoryType mongo"`
	Redis          infracache.RedisOptions
	OAuth          OAuthConfig
	SMTP           *infrasmtp.Config
	AppBaseURL     string `validate:"required_with=SMTP"` // password-reset link base
	Crypto         CryptoConfig
}

type CryptoConfig struct {
	EmailEncryptionKey string // base64, decodes to 32 bytes (AES-256)
	EmailBlindIndexKey string // base64 HMAC key
}

type FileRepositoryConfig struct {
	Dir                  string `validate:"required"`
	UserFileName         string `validate:"required"`
	RefreshTokenFileName string `validate:"required"`
}

type OAuthConfig struct {
	Clients                     []ClientConfig
	PostLogoutRedirectAllowlist []string
	ScopeAllowlist              []string
}

// ClientConfig declares one registered OAuth client. The first is parsed from
// the OAUTH_CLIENT_* vars; additional clients use OAUTH_CLIENT_<n>_* (n>=2).
// Each is parsed into an entity.Client at composition time.
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
		envPath, explicit := envFilePath(entryPath)
		if err := godotenv.Load(envPath); err != nil {
			if explicit || !errors.Is(err, fs.ErrNotExist) {
				log.Err(err).Msg("Failed to load environment variables")
				panic("Error loading environment variables")
			}
			log.Info().Str("path", envPath).Msg("no .env file found; using process environment")
		}

		cfg = &Settings{
			Server: coreweb.Config{
				Port:            normalizePort(os.Getenv("PORT")),
				CorsOrigins:     parseCorsOrigins(os.Getenv("CORS_ORIGINS")),
				CookieSecure:    os.Getenv("COOKIE_SECURE") == "true",
				MetricsAddr:     os.Getenv("METRICS_ADDR"),
				RateLimitPerMin: parseRateLimitPerMin(os.Getenv("RATE_LIMIT_PER_MIN")),
				RateLimitWindow: parseRateLimitWindow(os.Getenv("RATE_LIMIT_WINDOW")),
			},
			JWT: infrajwt.Config{
				PrivateKeyPath: os.Getenv("PRIVATE_KEY_PATH"),
				PublicKeyPath:  os.Getenv("PUBLIC_KEY_PATH"),
				Issuer:         os.Getenv("JWT_ISSUER"),
				Kid:            os.Getenv("JWT_KID"),
			},
			RepositoryType: os.Getenv("REPOSITORY_USED"),
			Redis: infracache.RedisOptions{
				Addr:     os.Getenv("REDIS_ADDR"),
				Password: os.Getenv("REDIS_PASSWORD"),
				DB:       parseRedisDB(os.Getenv("REDIS_DB")),
			},
			OAuth: OAuthConfig{
				Clients:                     parseClientConfigs(),
				PostLogoutRedirectAllowlist: parseCommaSeparated(os.Getenv("OAUTH_POST_LOGOUT_REDIRECT_ALLOWLIST")),
				ScopeAllowlist:              parseScopeAllowlist(os.Getenv("OAUTH_SCOPE_ALLOWLIST")),
			},
			AppBaseURL: os.Getenv("APP_BASE_URL"),
			Crypto: CryptoConfig{
				EmailEncryptionKey: os.Getenv("EMAIL_ENCRYPTION_KEY"),
				EmailBlindIndexKey: os.Getenv("EMAIL_BLIND_INDEX_KEY"),
			},
		}

		switch cfg.RepositoryType {
		case "mongo":
			cfg.Mongo = parseMongoConfig()
		default:
			cfg.FileRepository = parseFileRepositoryConfig()
		}

		if host := os.Getenv("SMTP_HOST"); host != "" {
			cfg.SMTP = &infrasmtp.Config{
				Host: host,
				Port: os.Getenv("SMTP_PORT"),
				From: os.Getenv("SMTP_FROM"),
			}
		}

		if err := validator.ValidateStruct(cfg); err != nil {
			log.Err(err).Msg("Failed to validate configuration")
			panic(err)
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

const (
	defaultRateLimitPerMin = 1000
	defaultRateLimitWindow = time.Minute
)

// parseRateLimitPerMin returns the per-window request cap. Unset falls back to
// the production default; an explicit 0 disables rate limiting (load/stress).
func parseRateLimitPerMin(raw string) int64 {
	if raw == "" {
		return defaultRateLimitPerMin
	}
	limit, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || limit < 0 {
		log.Error().Str("RATE_LIMIT_PER_MIN", raw).Msg("invalid RATE_LIMIT_PER_MIN value; must be a non-negative integer")
		panic("invalid RATE_LIMIT_PER_MIN configuration")
	}
	return limit
}

// parseRateLimitWindow returns the rate-limit window. Unset falls back to one
// minute; the value must be a positive Go duration (e.g. "1m", "30s").
func parseRateLimitWindow(raw string) time.Duration {
	if raw == "" {
		return defaultRateLimitWindow
	}
	window, err := time.ParseDuration(raw)
	if err != nil || window <= 0 {
		log.Error().Str("RATE_LIMIT_WINDOW", raw).Msg("invalid RATE_LIMIT_WINDOW value; must be a positive Go duration")
		panic("invalid RATE_LIMIT_WINDOW configuration")
	}
	return window
}

var (
	defaultClientRedirectURIs = []string{"https://app.example.com/callback", "http://localhost:3000/callback"}
	// All supported grants until per-client grant enforcement lands (finding #1).
	defaultClientAllowedGrants = []string{"authorization_code", "refresh_token", "password", "client_credentials"}
)

func parseFileRepositoryConfig() *FileRepositoryConfig {
	return &FileRepositoryConfig{
		Dir:                  os.Getenv("FILE_DIR"),
		UserFileName:         os.Getenv("USER_FILE_PATH"),
		RefreshTokenFileName: "refresh_tokens.json",
	}
}

func parseMongoConfig() *mongorepo.Config {
	return &mongorepo.Config{
		Host:       os.Getenv("MONGO_HOST"),
		Username:   os.Getenv("MONGO_USER"),
		Password:   os.Getenv("MONGO_PASSWORD"),
		AuthSource: os.Getenv("MONGO_AUTH_SOURCE"),
		Database:   os.Getenv("MONGO_DATABASE"),
		Direct:     true,
	}
}

// parseClientConfigs reads the primary client from OAUTH_CLIENT_* and any
// additional clients from OAUTH_CLIENT_<n>_* (n>=2), stopping at the first gap.
func parseClientConfigs() []ClientConfig {
	clients := []ClientConfig{parsePrimaryClientConfig()}
	for n := 2; ; n++ {
		prefix := "OAUTH_CLIENT_" + strconv.Itoa(n) + "_"
		id := os.Getenv(prefix + "ID")
		if id == "" {
			break
		}
		clients = append(clients, parseClientConfigFields(prefix, id))
	}
	return clients
}

func parsePrimaryClientConfig() ClientConfig {
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
	return parseClientConfigFields("OAUTH_CLIENT_", id)
}

// parseClientConfigFields reads a client's fields from the given env prefix,
// applying the shared defaults for auth method and allowed grants.
func parseClientConfigFields(prefix, id string) ClientConfig {
	authMethod := os.Getenv(prefix + "AUTH_METHOD")
	if authMethod == "" {
		authMethod = defaultClientAuthMethod
	}
	grants := parseCommaSeparated(os.Getenv(prefix + "ALLOWED_GRANTS"))
	if len(grants) == 0 {
		grants = defaultClientAllowedGrants
	}

	return ClientConfig{
		ID:            id,
		AuthMethod:    authMethod,
		Secret:        os.Getenv(prefix + "SECRET"),
		RedirectURIs:  parseCommaSeparated(os.Getenv(prefix + "REDIRECT_URIS")),
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

func normalizePort(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ":") {
		return raw
	}
	return ":" + raw
}

func envFilePath(entryPath string) (string, bool) {
	if f := os.Getenv("ENV_PATH"); f != "" {
		return f, true
	}
	return filepath.Join(entryPath, envFile), false
}
