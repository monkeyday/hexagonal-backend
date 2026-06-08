package query

import (
	"context"
	"fmt"

	corecache "sc/core/cache"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/port"
)

type IntrospectTokenQuery struct {
	Token         string  `form:"token"           json:"token"           validate:"required"`
	TokenTypeHint *string `form:"token_type_hint" json:"token_type_hint" validate:"omitempty,oneof=access_token refresh_token"`
}

type IntrospectTokenUseCase struct {
	jwtSvc port.TokenParser
	cache  corecache.ReadErrorCache
}

func NewIntrospectTokenUseCase(deps define.Dependencies) usecase.UseCase {
	return &IntrospectTokenUseCase{jwtSvc: deps.JWTSvc, cache: deps.Cache}
}

// Execute introspects the submitted token per RFC 7662.
// token_type_hint is advisory: if the hinted type cannot confirm the token, supported types
// are tried anyway. Introspection supports only access tokens (JWT); opaque refresh tokens
// always return inactive regardless of hint.
func (uc *IntrospectTokenUseCase) Execute(ctx context.Context, q any) (any, error) {
	query := q.(*IntrospectTokenQuery)

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
