package query

import (
	"context"
	"sc/modules/auth/application/define"
	"sc/modules/auth/port"
)

type GetJWKSQuery struct{}

type GetJWKSUseCase struct {
	jwks port.JWKSProvider
}

func NewGetJWKSUseCase(deps define.Dependencies) *GetJWKSUseCase {
	return &GetJWKSUseCase{jwks: deps.JWTSvc}
}

func (uc *GetJWKSUseCase) Execute(ctx context.Context, query any) (any, error) {
	return uc.jwks.GetJWKS(), nil
}
