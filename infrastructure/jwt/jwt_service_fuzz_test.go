package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// FuzzParseJWT feeds arbitrary token strings through the parsers. Both must
// survive any input without panicking, and a nil error must always come with
// non-nil claims (never a silent accept of a malformed token).
func FuzzParseJWT(f *testing.F) {
	svc := newTestService(f)

	access, err := svc.GenAccessToken("user-1", "openid email", 3600)
	if err != nil {
		f.Fatalf("GenAccessToken: %v", err)
	}
	id, err := svc.GenIDToken("user-1", "client-1", "a@b.io", "nonce", true, 3600)
	if err != nil {
		f.Fatalf("GenIDToken: %v", err)
	}
	for _, s := range []string{
		access,
		id,
		"",
		"a",
		"a.b",
		"a.b.c",
		"eyJhbGciOiJub25lIn0.e30.", // alg=none, empty signature
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, tok string) {
		if claims, err := svc.ParseJWT(tok); err == nil && claims == nil {
			t.Fatalf("ParseJWT: nil error but nil claims for %q", tok)
		}
		if claims, err := svc.ParseIDToken(tok); err == nil && claims == nil {
			t.Fatalf("ParseIDToken: nil error but nil claims for %q", tok)
		}
	})
}

// FuzzParseJWT_ForgedSignature signs attacker-controlled claims with a foreign
// RSA key. The claims are shaped to satisfy every other check (issuer,
// audience, token_use, expiry), so the only thing standing between the forged
// token and acceptance is signature verification — which must always reject it.
func FuzzParseJWT_ForgedSignature(f *testing.F) {
	svc := newTestService(f)

	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate attacker key: %v", err)
	}

	f.Add("user-1", "openid", testIssuer, accessTokenAudience)
	f.Add("admin", "openid email profile", "https://evil.test", "other-api")

	f.Fuzz(func(t *testing.T, sub, scope, iss, aud string) {
		now := time.Now()

		access := jwt.MapClaims{
			"sub":         sub,
			"scope":       scope,
			"iss":         iss,
			"aud":         aud,
			"iat":         now.Unix(),
			"exp":         now.Add(time.Hour).Unix(),
			"jti":         "forged",
			tokenUseClaim: tokenUseAccess,
		}
		forged, err := jwt.NewWithClaims(jwt.SigningMethodRS256, access).SignedString(attacker)
		if err != nil {
			t.Fatalf("sign forged access token: %v", err)
		}
		if _, err := svc.ParseJWT(forged); err == nil {
			t.Fatalf("ParseJWT accepted a token signed by a foreign key (sub=%q iss=%q aud=%q)", sub, iss, aud)
		}

		idc := jwt.MapClaims{
			"sub":            sub,
			"iss":            iss,
			"aud":            aud,
			"iat":            now.Unix(),
			"exp":            now.Add(time.Hour).Unix(),
			"email":          "a@b.io",
			"email_verified": true,
			tokenUseClaim:    tokenUseID,
		}
		forgedID, err := jwt.NewWithClaims(jwt.SigningMethodRS256, idc).SignedString(attacker)
		if err != nil {
			t.Fatalf("sign forged id token: %v", err)
		}
		if _, err := svc.ParseIDToken(forgedID); err == nil {
			t.Fatalf("ParseIDToken accepted a token signed by a foreign key (sub=%q iss=%q)", sub, iss)
		}
	})
}
