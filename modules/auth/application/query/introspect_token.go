package query

import (
	"context"
	"fmt"

	corecache "sc/core/cache"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/application/service"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
)

type IntrospectTokenQuery struct {
	ClientID          string  `form:"client_id" json:"client_id"`
	ClientSecret      string  `form:"client_secret" json:"client_secret"`
	BasicClientID     string  `ctx:"basic_client_id"`
	BasicClientSecret string  `ctx:"basic_client_secret"`
	Token             string  `form:"token"           json:"token"           validate:"required"`
	TokenTypeHint     *string `form:"token_type_hint" json:"token_type_hint" validate:"omitempty,oneof=access_token refresh_token"`
}

type IntrospectTokenUseCase struct {
	jwtSvc              port.TokenParser
	cache               corecache.ReadErrorCache
	clientAuthenticator *service.ClientAuthenticator
}

func NewIntrospectTokenUseCase(deps define.Dependencies) usecase.UseCase {
	return &IntrospectTokenUseCase{
		jwtSvc:              deps.JWTSvc,
		cache:               deps.Cache,
		clientAuthenticator: service.NewClientAuthenticator(deps.ClientRegistry),
	}
}

// Execute introspects the submitted token per RFC 7662.
// token_type_hint is advisory: if the hinted type cannot confirm the token, supported types
// are tried anyway. Introspection supports only access tokens (JWT); opaque refresh tokens
// always return inactive regardless of hint.
func (uc *IntrospectTokenUseCase) Execute(ctx context.Context, q any) (any, error) {
	query := q.(*IntrospectTokenQuery)

	if err := uc.authorizeCaller(ctx, query); err != nil {
		return nil, err
	}

	claims, err := uc.jwtSvc.ParseJWT(query.Token)
	if err != nil || claims == nil {
		return &define.IntrospectResponse{Active: false}, nil
	}

	// Fail-closed on blacklist errors, matching Authenticate middleware behaviour.
	if claims.ID != "" && uc.cache != nil {
		revoked, err := uc.cache.GetErr(ctx, fmt.Sprintf(define.BlacklistCacheKey, claims.ID), nil)
		if err != nil || revoked {
			return &define.IntrospectResponse{Active: false}, nil
		}
	}

	resp := &define.IntrospectResponse{
		Active:    true,
		Sub:       claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Scope:     claims.Scope,
		TokenType: define.TokenTypeBearer,
	}
	if claims.ExpiresAt != nil {
		resp.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		resp.IssuedAt = claims.IssuedAt.Unix()
	}
	if claims.ID != "" {
		resp.JWTID = claims.ID
	}
	return resp, nil
}

// authorizeCaller enforces RFC 7662 §2.1: introspection must never be open.
// Only an authenticated confidential client may introspect. A bearer token or
// a bare public client_id is not enough — either would turn introspection
// into a token oracle for any end user holding a valid access token.
func (uc *IntrospectTokenUseCase) authorizeCaller(ctx context.Context, q *IntrospectTokenQuery) error {
	if q.ClientID == "" && q.BasicClientID == "" {
		return autherrors.NewErrInvalidClient()
	}
	client, err := uc.clientAuthenticator.Authenticate(ctx, service.ClientCredentials{
		ClientID:      q.ClientID,
		FormSecret:    q.ClientSecret,
		BasicClientID: q.BasicClientID,
		BasicSecret:   q.BasicClientSecret,
	})
	if err != nil || client.IsPublic() {
		return autherrors.NewErrInvalidClient()
	}
	return nil
}
