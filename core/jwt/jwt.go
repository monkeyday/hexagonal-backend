package jwt

import "time"

// JWK is the JSON Web Key representation used for JWKS endpoints.
type JWK struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

// Claims holds parsed access-token fields as plain Go types.
// Kept in core so the HTTP middleware can verify tokens without importing auth-specific ports.
type Claims struct {
	Subject   string
	Scope     string
	Issuer    string
	Audience  []string
	ID        string // JWT ID (jti claim)
	ExpiresAt *time.Time
	IssuedAt  *time.Time
}

func (c *Claims) IsExpired() bool {
	return c.ExpiresAt == nil || time.Now().After(*c.ExpiresAt)
}

// IDTokenClaims holds parsed ID-token fields as plain Go types.
type IDTokenClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Nonce         string
	ExpiresAt     *time.Time
}
