package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const testIssuer = "https://issuer.test"

func newTestService(t *testing.T) *JWTService {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	svc, err := NewJWTService(Config{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		Issuer:         testIssuer,
		Kid:            "test-kid",
	})
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	t.Cleanup(svc.Close)
	return svc
}

func signRaw(t *testing.T, svc *JWTService, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(svc.privateKey)
	if err != nil {
		t.Fatalf("sign raw token: %v", err)
	}
	return s
}

func baseAccessClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"sub":         "user-1",
		"aud":         accessTokenAudience,
		"scope":       "openid",
		"iat":         now.Unix(),
		"exp":         now.Add(time.Hour).Unix(),
		"jti":         "jti-1",
		"iss":         testIssuer,
		tokenUseClaim: tokenUseAccess,
	}
}

func TestParseJWT(t *testing.T) {
	svc := newTestService(t)

	tests := []struct {
		name    string
		token   func(t *testing.T) string
		wantErr string
	}{
		{
			name: "generated access token — accepted with subject, scope and jti",
			token: func(t *testing.T) string {
				s, err := svc.GenAccessToken("user-1", "openid email", 3600)
				if err != nil {
					t.Fatalf("GenAccessToken: %v", err)
				}
				return s
			},
		},
		{
			name: "ID token presented as bearer — rejected",
			token: func(t *testing.T) string {
				s, err := svc.GenIDToken("user-1", "client-123", "a@b.io", "nonce", true, 3600)
				if err != nil {
					t.Fatalf("GenIDToken: %v", err)
				}
				return s
			},
			wantErr: "audience",
		},
		{
			name: "wrong issuer — rejected",
			token: func(t *testing.T) string {
				c := baseAccessClaims()
				c["iss"] = "https://evil.test"
				return signRaw(t, svc, c)
			},
			wantErr: "issuer",
		},
		{
			name: "wrong audience — rejected",
			token: func(t *testing.T) string {
				c := baseAccessClaims()
				c["aud"] = "other-api"
				return signRaw(t, svc, c)
			},
			wantErr: "audience",
		},
		{
			name: "missing token_use — rejected (pre-rollout token shape)",
			token: func(t *testing.T) string {
				c := baseAccessClaims()
				delete(c, tokenUseClaim)
				return signRaw(t, svc, c)
			},
			wantErr: "not an access token",
		},
		{
			name: "token_use id with access audience — rejected",
			token: func(t *testing.T) string {
				c := baseAccessClaims()
				c[tokenUseClaim] = tokenUseID
				return signRaw(t, svc, c)
			},
			wantErr: "not an access token",
		},
		{
			name: "expired access token — rejected",
			token: func(t *testing.T) string {
				c := baseAccessClaims()
				c["exp"] = time.Now().Add(-time.Minute).Unix()
				return signRaw(t, svc, c)
			},
			wantErr: "expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := svc.ParseJWT(tc.token(t))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if claims.Subject != "user-1" {
				t.Errorf("Subject = %q, want user-1", claims.Subject)
			}
			if claims.Scope != "openid email" {
				t.Errorf("Scope = %q, want %q", claims.Scope, "openid email")
			}
			if claims.ID == "" {
				t.Error("jti must always be set on access tokens")
			}
		})
	}
}

func TestParseIDToken(t *testing.T) {
	svc := newTestService(t)

	t.Run("generated ID token — accepted", func(t *testing.T) {
		s, err := svc.GenIDToken("user-1", "client-123", "a@b.io", "nonce-1", true, 3600)
		if err != nil {
			t.Fatalf("GenIDToken: %v", err)
		}
		claims, err := svc.ParseIDToken(s)
		if err != nil {
			t.Fatalf("ParseIDToken: %v", err)
		}
		if claims.Subject != "user-1" || claims.Email != "a@b.io" || claims.Nonce != "nonce-1" {
			t.Errorf("claims = %+v, want subject user-1, email a@b.io, nonce nonce-1", claims)
		}
	})

	t.Run("access token presented as ID token — rejected", func(t *testing.T) {
		s, err := svc.GenAccessToken("user-1", "openid", 3600)
		if err != nil {
			t.Fatalf("GenAccessToken: %v", err)
		}
		if _, err := svc.ParseIDToken(s); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestGetJWKS_MinimalOctetEncoding(t *testing.T) {
	svc := newTestService(t)

	keys := svc.GetJWKS()["keys"]
	if len(keys) != 1 {
		t.Fatalf("expected 1 JWK, got %d", len(keys))
	}
	jwk := keys[0]

	// RFC 7518 §6.3.1: 65537 must encode as "AQAB", not zero-padded "AAEAAQ".
	if jwk.E != "AQAB" {
		t.Errorf("e = %q, want AQAB", jwk.E)
	}

	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("n is not valid base64url: %v", err)
	}
	if len(n) == 0 || n[0] == 0x00 {
		t.Errorf("n must be a minimal-octet value without a leading zero, first byte = %#x", n[0])
	}
	if len(n) != 256 {
		t.Errorf("n length = %d bytes, want 256 for a 2048-bit key", len(n))
	}
}
