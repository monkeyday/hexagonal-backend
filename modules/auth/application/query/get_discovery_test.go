package query

import (
	"context"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	"strings"
	"testing"
)

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

func TestGetDiscoveryUseCase(t *testing.T) {
	const issuer = "https://auth.example.com"

	jwtSvc := &mockJwtService{issuer: issuer}
	uc := NewGetDiscoveryUseCase(define.Dependencies{JWTSvc: jwtSvc})

	result, err := uc.Execute(context.Background(), &GetDiscoveryQuery{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	doc, ok := result.(*DiscoveryResponse)
	if !ok {
		t.Fatalf("expected *DiscoveryResponse, got %T", result)
	}

	t.Run("issuer matches jwt service issuer", func(t *testing.T) {
		if doc.Issuer != issuer {
			t.Fatalf("issuer = %q, want %q", doc.Issuer, issuer)
		}
	})

	t.Run("all endpoints are prefixed by issuer", func(t *testing.T) {
		base := strings.TrimRight(issuer, "/")
		want := map[string]string{
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"userinfo_endpoint":      base + "/userinfo",
			"jwks_uri":               base + "/.well-known/jwks.json",
			"revocation_endpoint":    base + "/oidc/revoke",
			"end_session_endpoint":   base + "/oidc/logout",
			"introspection_endpoint": base + "/oidc/introspect",
		}
		got := map[string]string{
			"authorization_endpoint": doc.AuthorizationEndpoint,
			"token_endpoint":         doc.TokenEndpoint,
			"userinfo_endpoint":      doc.UserinfoEndpoint,
			"jwks_uri":               doc.JWKSURI,
			"revocation_endpoint":    doc.RevocationEndpoint,
			"end_session_endpoint":   doc.EndSessionEndpoint,
			"introspection_endpoint": doc.IntrospectionEndpoint,
		}
		for field, wantVal := range want {
			if got[field] != wantVal {
				t.Errorf("%s = %q, want %q", field, got[field], wantVal)
			}
		}
	})

	t.Run("issuer with trailing slash: endpoints use trimmed base, issuer preserved", func(t *testing.T) {
		uc2 := NewGetDiscoveryUseCase(define.Dependencies{JWTSvc: &mockJwtService{issuer: issuer + "/"}})
		result2, err := uc2.Execute(context.Background(), &GetDiscoveryQuery{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		doc2 := result2.(*DiscoveryResponse)
		if doc2.Issuer != issuer+"/" {
			t.Errorf("issuer = %q, want %q (trailing slash preserved)", doc2.Issuer, issuer+"/")
		}
		if doc2.TokenEndpoint != issuer+"/token" {
			t.Errorf("token_endpoint = %q, want %q", doc2.TokenEndpoint, issuer+"/token")
		}
	})

	t.Run("RS256 is the only signing algorithm", func(t *testing.T) {
		algs := doc.IDTokenSigningAlgValuesSupported
		if len(algs) != 1 || algs[0] != "RS256" {
			t.Errorf("signing algs = %v, want [RS256]", algs)
		}
	})

	t.Run("grant_types_supported is exactly the expected set", func(t *testing.T) {
		want := []string{"authorization_code", "password", "refresh_token"}
		if !sameStringSet(doc.GrantTypesSupported, want) {
			t.Errorf("grant_types_supported = %v, want exactly %v", doc.GrantTypesSupported, want)
		}
	})

	t.Run("scopes_supported matches entity.SupportedScopes exactly", func(t *testing.T) {
		if !sameStringSet(doc.ScopesSupported, entity.SupportedScopes) {
			t.Errorf("scopes_supported = %v, want %v", doc.ScopesSupported, entity.SupportedScopes)
		}
	})

	t.Run("token_endpoint_auth_methods_supported is exactly [none]", func(t *testing.T) {
		want := []string{"none"}
		if !sameStringSet(doc.TokenEndpointAuthMethods, want) {
			t.Errorf("token_endpoint_auth_methods_supported = %v, want exactly %v", doc.TokenEndpointAuthMethods, want)
		}
	})

	t.Run("S256 is the only PKCE method", func(t *testing.T) {
		methods := doc.CodeChallengeMethodsSupported
		if len(methods) != 1 || methods[0] != entity.CodeChallengeMethodS256 {
			t.Errorf("code_challenge_methods_supported = %v, want [%s]", methods, entity.CodeChallengeMethodS256)
		}
	})

	t.Run("claims_supported includes sub and email", func(t *testing.T) {
		needed := []string{"sub", "email"}
		for _, c := range needed {
			found := false
			for _, s := range doc.ClaimsSupported {
				if s == c {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("claims_supported missing %q", c)
			}
		}
	})
}
