package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	corejwt "sc/core/jwt"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	tokenUseClaim  = "token_use"
	tokenUseAccess = "access"
	tokenUseID     = "id"
	// TODO: replace with audience(s) from client registry once built
	accessTokenAudience = "APP_ID"
)

var (
	once sync.Once
	svc  *JWTService
)

type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey // cached — avoids re-decoding on every verification
	jwk        corejwt.JWK
	Issuer     string
	kid        string
}

func NewJWTService(cfg Config) (*JWTService, error) {
	var err error
	once.Do(func() {
		privateKey, err1 := loadPrivateKey(cfg.PrivateKeyPath)
		if err1 != nil {
			err = err1
			return
		}
		publicKey, jwk, err2 := loadPublicKeyAndJWK(cfg.PublicKeyPath, cfg.Kid)
		if err2 != nil {
			err = err2
			return
		}
		svc = &JWTService{
			privateKey: privateKey,
			publicKey:  publicKey,
			jwk:        jwk,
			Issuer:     cfg.Issuer,
			kid:        cfg.Kid,
		}
	})
	if err != nil {
		once = sync.Once{} // reset for retry if needed
		return nil, err
	}
	return svc, nil
}

func (j *JWTService) Close() {
	once = sync.Once{}
	svc = nil
}

func (j *JWTService) GenAccessToken(userID, scope string, expireSecs int) (string, error) {
	now := time.Now()
	return j.signToken(jwt.MapClaims{
		"sub":         userID,
		"aud":         accessTokenAudience,
		"scope":       scope,
		"iat":         now.Unix(),
		"exp":         now.Add(time.Second * time.Duration(expireSecs)).Unix(),
		"jti":         uuid.NewString(),
		"iss":         j.Issuer,
		tokenUseClaim: tokenUseAccess,
	}, userID)
}

func (j *JWTService) GenRefreshToken(userID string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("gen random bytes failed for user %s: %w", userID, err)
	}
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

func (j *JWTService) GenIDToken(userID, clientID, email, nonce string, emailVerified bool, expireSecs int) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            j.Issuer,
		"sub":            userID,
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Second * time.Duration(expireSecs)).Unix(),
		"email":          email,
		"email_verified": emailVerified,
		tokenUseClaim:    tokenUseID,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return j.signToken(claims, userID)
}

func (j *JWTService) GetJWKS() map[string][]corejwt.JWK {
	return map[string][]corejwt.JWK{"keys": {j.jwk}}
}

func (j *JWTService) GetIssuer() string { return j.Issuer }

type accessTokenClaims struct {
	jwt.RegisteredClaims
	Scope    string `json:"scope"`
	TokenUse string `json:"token_use"`
}

type idTokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Nonce         string `json:"nonce,omitempty"`
	TokenUse      string `json:"token_use"`
}

func (j *JWTService) ParseJWT(tokenString string) (*corejwt.Claims, error) {
	var c accessTokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &c, j.verifyByKey)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	parsed := token.Claims.(*accessTokenClaims)
	if parsed.Issuer != j.Issuer {
		return nil, errors.New("invalid issuer")
	}
	if !slices.Contains(parsed.Audience, accessTokenAudience) {
		return nil, errors.New("invalid audience")
	}
	if parsed.TokenUse != tokenUseAccess {
		return nil, errors.New("not an access token")
	}
	out := &corejwt.Claims{
		Subject:  parsed.Subject,
		Scope:    parsed.Scope,
		Issuer:   parsed.Issuer,
		Audience: []string(parsed.Audience),
		ID:       parsed.ID,
	}
	if parsed.ExpiresAt != nil {
		out.ExpiresAt = &parsed.ExpiresAt.Time
	}
	if parsed.IssuedAt != nil {
		out.IssuedAt = &parsed.IssuedAt.Time
	}
	return out, nil
}

func (j *JWTService) ParseIDToken(tokenString string) (*corejwt.IDTokenClaims, error) {
	var c idTokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &c, j.verifyByKey)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	parsed := token.Claims.(*idTokenClaims)
	if parsed.Issuer != j.Issuer {
		return nil, errors.New("invalid issuer")
	}
	if parsed.TokenUse != tokenUseID {
		return nil, errors.New("not an ID token")
	}
	out := &corejwt.IDTokenClaims{
		Subject:       parsed.Subject,
		Email:         parsed.Email,
		EmailVerified: parsed.EmailVerified,
		Nonce:         parsed.Nonce,
	}
	if parsed.ExpiresAt != nil {
		out.ExpiresAt = &parsed.ExpiresAt.Time
	}
	return out, nil
}

func (j *JWTService) signToken(claims jwt.MapClaims, userID string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = claims
	token.Header["kid"] = j.kid
	s, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", err
	}
	return s, nil
}

func (j *JWTService) verifyByKey(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("invalid signing method: %s", token.Header["alg"])
	}
	return j.publicKey, nil // cached at startup, no per-request conversion
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key failed at %s: %w", path, err)
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(b)
	if err != nil {
		return nil, fmt.Errorf("parse private key failed at %s: %w", path, err)
	}
	return key, nil
}

func loadPublicKeyAndJWK(path, kid string) (*rsa.PublicKey, corejwt.JWK, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, corejwt.JWK{}, fmt.Errorf("read public key failed at %s: %w", path, err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(b)
	if err != nil {
		return nil, corejwt.JWK{}, fmt.Errorf("parse public key failed at %s: %w", path, err)
	}

	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(key.E))

	return key, corejwt.JWK{
		Kty: "RSA",
		E:   base64.RawURLEncoding.EncodeToString(bs),
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		Alg: "RS256",
		Use: "sig",
		Kid: kid,
	}, nil
}
