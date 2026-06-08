package web

const CookieSecureKey = "cookie_secure"

type Config struct {
	Port         string `validate:"required"`
	CorsOrigins  []string
	CookieSecure bool
}
