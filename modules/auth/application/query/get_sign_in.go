package query

import (
	"context"
	"fmt"

	corecache "sc/core/cache"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
)

type GetSignInQuery struct {
	SessionID string `cookie:"auth_session" validate:"required,uuid"`
}

type GetSignInUseCase struct {
	cache corecache.ReadErrorCache
}

func NewGetSignInUseCase(deps define.Dependencies) usecase.UseCase {
	return &GetSignInUseCase{cache: deps.Cache}
}

func (uc *GetSignInUseCase) Execute(ctx context.Context, query any) (any, error) {
	q := query.(*GetSignInQuery)

	var session entity.AuthorizeRequest
	ok, err := uc.cache.GetErr(ctx, fmt.Sprintf(define.AuthorizeRequestCacheKey, q.SessionID), &session)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, autherrors.NewErrInvalidSession()
	}
	if err := session.Validate(); err != nil {
		return nil, autherrors.NewErrInvalidSession()
	}

	return &define.GetSignInResponse{CSRFToken: session.CSRFToken}, nil
}
