package web

const CookieSecureKey = "cookie_secure"

type Config struct {
	Port         string `validate:"required"`
	CorsOrigins  []string
	CookieSecure bool
	// MetricsAddr is the listen address for the internal-only metrics
	// endpoint (/debug/vars). Empty disables it. Never expose publicly.
	MetricsAddr string
}
