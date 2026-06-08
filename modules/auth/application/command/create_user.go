package command

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

type CreateUserCommand struct {
	Username string `form:"username" validate:"required"`
	Nickname string `form:"nickname" validate:"required"`
	Email    string `form:"email" validate:"required,email"`
	Password string `form:"password" validate:"required,passwordPattern"`
}

type CreateUserUseCase struct {
	userRepo port.UserRepository
}

func NewCreateUserUseCase(deps define.Dependencies) usecase.UseCase {
	return &CreateUserUseCase{userRepo: deps.UserRepo}
}

func (uc *CreateUserUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*CreateUserCommand)

	user, err := entity.NewUser(entity.UserArgs{
		Username:      c.Username,
		Nickname:      c.Nickname,
		Password:      c.Password,
		Email:         c.Email,
		EmailVerified: false,
	})
	if err != nil {
		return nil, autherrors.NewErrInvalidUserArguments(err)
	}
	if err := uc.userRepo.CreateUser(ctx, user); err != nil {
		if errors.Is(err, coreerror.ErrConflict) {
			return nil, autherrors.NewErrEmailDuplicated()
		}
		return nil, autherrors.NewErrCreateUser(err)
	}

	res := &define.CreateUserResponse{}
	res.FromEntity(user)
	return res, nil
}
