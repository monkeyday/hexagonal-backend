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

type UpdateProfileCommand struct {
	UserID   string  `ctx:"user_id" validate:"required"`
	Username *string `form:"username"`
	Nickname *string `form:"nickname"`
	Email    *string `form:"email" validate:"omitempty,email"`
}

type UpdateProfileUseCase struct {
	userRepo port.UserRepository
}

func NewUpdateProfileUseCase(deps define.Dependencies) usecase.UseCase {
	return &UpdateProfileUseCase{userRepo: deps.UserRepo}
}

func (uc *UpdateProfileUseCase) checkEmailAvailable(ctx context.Context, tenantID entity.TenantID, email string, excludeID entity.UserID) error {
	userExists, err := uc.userRepo.FindByEmail(ctx, tenantID, email)
	if err != nil && !errors.Is(err, coreerror.ErrNotFound) {
		return err
	}
	if userExists != nil && userExists.ID != excludeID {
		return autherrors.NewErrEmailDuplicated()
	}
	return nil
}

func (uc *UpdateProfileUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*UpdateProfileCommand)

	user, err := uc.userRepo.FindByID(ctx, entity.UserID(c.UserID))
	if err != nil {
		if errors.Is(err, coreerror.ErrNotFound) {
			return &define.UpdateProfileResponse{}, autherrors.NewErrInvalidToken()
		}
		return &define.UpdateProfileResponse{}, autherrors.NewErrUpdateProfileFindFailed(err)
	}
	if user == nil {
		return &define.UpdateProfileResponse{}, autherrors.NewErrInvalidToken()
	}

	if c.Email != nil {
		if err := uc.checkEmailAvailable(ctx, user.TenantID, *c.Email, entity.UserID(c.UserID)); err != nil {
			return &define.UpdateProfileResponse{}, err
		}
	}

	updated := *user
	updated.UpdateProfile(entity.UpdateProfileArgs{
		Username: c.Username,
		Nickname: c.Nickname,
		Email:    c.Email,
	})
	if err := uc.userRepo.Save(ctx, &updated); err != nil {
		return &define.UpdateProfileResponse{}, autherrors.NewErrUpdateProfile(err)
	}

	return &define.UpdateProfileResponse{
		UserID:        string(updated.ID),
		Email:         updated.Email,
		Username:      updated.Username,
		Nickname:      updated.Nickname,
		EmailVerified: updated.EmailVerified,
		UpdatedAt:     updated.UpdatedAt,
	}, nil
}
