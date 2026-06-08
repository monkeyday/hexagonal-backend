package query

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
)

type GetProfileQuery struct {
	UserID string `ctx:"user_id" validate:"required"`
}

type GetProfileUseCase struct {
	userRepo port.UserRepository
}

func NewGetProfileUseCase(deps define.Dependencies) usecase.UseCase {
	return &GetProfileUseCase{userRepo: deps.UserRepo}
}

func (uc *GetProfileUseCase) Execute(ctx context.Context, query any) (any, error) {
	q := query.(*GetProfileQuery)

	user, err := uc.userRepo.FindByID(ctx, entity.UserID(q.UserID))
	if errors.Is(err, coreerror.ErrNotFound) {
		return nil, autherrors.NewErrInvalidToken()
	}
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, autherrors.NewErrInvalidToken()
	}

	return &define.GetProfileResponse{
		Sub:               string(user.ID),
		PreferredUsername: user.Username,
		Nickname:          user.Nickname,
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		UpdatedAt:         user.UpdatedAt.Unix(),
	}, nil
}
