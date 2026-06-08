package adapter

import (
	corejwt "sc/core/jwt"
	infrajwt "sc/infrastructure/jwt"
	"sc/modules/auth/port"
)

var _ port.TokenService = (*JWTServiceAdapter)(nil)

// JWTServiceAdapter adapts infrastructure/jwt.JWTService to port.TokenService.
// It translates the IDTokenArgs struct into the infrastructure's positional signature.
type JWTServiceAdapter struct {
	svc *infrajwt.JWTService
}

func NewJWTServiceAdapter(svc *infrajwt.JWTService) port.TokenService {
	return &JWTServiceAdapter{svc: svc}
}

func (a *JWTServiceAdapter) GenAccessToken(userID, scope string, expireSecs int) (string, error) {
	return a.svc.GenAccessToken(userID, scope, expireSecs)
}

func (a *JWTServiceAdapter) GenRefreshToken(userID string) (string, error) {
	return a.svc.GenRefreshToken(userID)
}

func (a *JWTServiceAdapter) GenIDToken(args port.IDTokenArgs) (string, error) {
	return a.svc.GenIDToken(args.UserID, args.ClientID, args.Email, args.Nonce, args.EmailVerified, args.ExpireSecs)
}

func (a *JWTServiceAdapter) ParseJWT(tokenString string) (*corejwt.Claims, error) {
	return a.svc.ParseJWT(tokenString)
}

func (a *JWTServiceAdapter) ParseIDToken(tokenString string) (*corejwt.IDTokenClaims, error) {
	return a.svc.ParseIDToken(tokenString)
}

func (a *JWTServiceAdapter) GetJWKS() map[string][]corejwt.JWK {
	return a.svc.GetJWKS()
}

func (a *JWTServiceAdapter) GetIssuer() string {
	return a.svc.GetIssuer()
}
