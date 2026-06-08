package query

import (
	"context"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	"strings"
)

type GetDiscoveryQuery struct{}

type DiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

type GetDiscoveryUseCase struct {
	issuer      string
	endpointURL string
}

func NewGetDiscoveryUseCase(deps define.Dependencies) *GetDiscoveryUseCase {
	issuer := deps.JWTSvc.GetIssuer()
	return &GetDiscoveryUseCase{
		issuer:      issuer,
		endpointURL: strings.TrimRight(issuer, "/"),
	}
}

func (uc *GetDiscoveryUseCase) Execute(_ context.Context, _ any) (any, error) {
	return &DiscoveryResponse{
		Issuer:                           uc.issuer,
		AuthorizationEndpoint:            uc.endpointURL + "/authorize",
		TokenEndpoint:                    uc.endpointURL + "/token",
		UserinfoEndpoint:                 uc.endpointURL + "/userinfo",
		JWKSURI:                          uc.endpointURL + "/.well-known/jwks.json",
		RevocationEndpoint:               uc.endpointURL + "/oidc/revoke",
		EndSessionEndpoint:               uc.endpointURL + "/oidc/logout",
		IntrospectionEndpoint:            uc.endpointURL + "/oidc/introspect",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  entity.SupportedScopes,
		GrantTypesSupported:              []string{"authorization_code", "password", "refresh_token"},
		TokenEndpointAuthMethods:         []string{"none"},
		CodeChallengeMethodsSupported:    []string{entity.CodeChallengeMethodS256},
		ClaimsSupported:                  []string{"sub", "email", "email_verified", "preferred_username", "nickname", "updated_at"},
	}, nil
}
