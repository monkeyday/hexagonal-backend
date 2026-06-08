package command

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	coreuow "sc/core/uow"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

type ResetPasswordCommand struct {
	Token    string `form:"token"    json:"token"    validate:"required"`
	Password string `form:"password" json:"password" validate:"required"`
}

type ResetPasswordUseCase struct {
	userRepo         port.UserRepository
	refreshTokenRepo port.RefreshTokenRepository
	uow              coreuow.UnitOfWork
}

func NewResetPasswordUseCase(deps define.Dependencies) usecase.UseCase {
	return &ResetPasswordUseCase{
		userRepo:         deps.UserRepo,
		refreshTokenRepo: deps.RefreshTokenRepo,
		uow:              deps.UoW,
	}
}

func (uc *ResetPasswordUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*ResetPasswordCommand)

	var userID entity.UserID
	_, err := uc.uow.Do(ctx, func(ctx context.Context) (any, error) {
		return nil, uc.userRepo.UpdateByPasswordResetTokenHash(ctx, entity.Hash(c.Token), func(u *entity.User) error {
			if u.IsResetTokenExpired() {
				return autherrors.NewErrPasswordResetTokenExpired()
			}
			if err := u.SetPassword(c.Password); err != nil {
				return autherrors.NewErrWeakPassword(err)
			}
			userID = u.ID
			u.InvalidateSessions()
			u.ClearPasswordResetToken()
			return nil
		})
	})
	if err != nil {
		if errors.Is(err, coreerror.ErrNotFound) {
			return nil, autherrors.NewErrPasswordResetTokenNotFound()
		}
		if _, ok := err.(*coreerror.ErrorStruct); ok {
			return nil, err
		}
		return nil, autherrors.NewErrResetPasswordFailed(err)
	}

	if err := uc.refreshTokenRepo.RevokeAllForUser(ctx, userID); err != nil {
		log.Error().Err(err).Str("user_id", string(userID)).Msg("reset_password: failed to revoke refresh tokens")
	}

	return nil, nil
}
