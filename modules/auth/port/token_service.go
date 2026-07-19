package port

import (
	corejwt "sc/core/jwt"
)

// IDTokenArgs groups the parameters for ID-token generation.
type IDTokenArgs struct {
	UserID        string
	ClientID      string
	Email         string
	Nonce         string
	EmailVerified bool
	ExpireSecs    int
}

// TokenIssuer generates access, refresh, and ID tokens.
type TokenIssuer interface {
	GenAccessToken(userID, scope string, expireSecs int) (string, error)
	GenRefreshToken(userID string) (string, error)
	GenIDToken(args IDTokenArgs) (string, error)
}

// TokenParser verifies and parses bearer and ID tokens.
type TokenParser interface {
	ParseJWT(tokenString string) (*corejwt.Claims, error)
	ParseIDToken(tokenString string) (*corejwt.IDTokenClaims, error)
}

// JWKSProvider exposes the public key set and issuer for discovery/JWKS endpoints.
type JWKSProvider interface {
	GetJWKS() map[string][]corejwt.JWK
	GetIssuer() string
}

// TokenService is the combined interface carried by define.Dependencies.
// Individual use cases should depend only on the narrower sub-interface they call.
type TokenService interface {
	TokenIssuer
	TokenParser
	JWKSProvider
}
