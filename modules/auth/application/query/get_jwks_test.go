package query

import (
	"context"
	corejwt "sc/core/jwt"
	"sc/modules/auth/application/define"
	"testing"
)

func TestGetJWKSUseCase(t *testing.T) {
	ctx := context.Background()
	jwt := &mockJwtService{}
	uc := NewGetJWKSUseCase(define.Dependencies{JWTSvc: jwt})

	result, err := uc.Execute(ctx, &GetJWKSQuery{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	jwks, ok := result.(map[string][]corejwt.JWK)
	if !ok {
		t.Fatalf("expected JWKS map, got %T", result)
	}
	keys, ok := jwks["keys"]
	if !ok {
		t.Fatal("response missing 'keys' field")
	}
	if len(keys) == 0 {
		t.Fatal("keys slice should not be empty")
	}
	if keys[0].Kid != "test-kid" {
		t.Fatalf("kid = %q, want test-kid", keys[0].Kid)
	}
	if keys[0].Kty != "RSA" {
		t.Fatalf("kty = %q, want RSA", keys[0].Kty)
	}
}
