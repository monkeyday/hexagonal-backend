package command

import (
	"context"
	"errors"
	"sc/core/event"
	"time"

	coreerror "sc/core/error"
	coreuow "sc/core/uow"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/application/service"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

type ResetPasswordCommand struct {
	Token    string `form:"token"    json:"token"    validate:"required"`
	Password string `form:"password" json:"password" validate:"required"`
}

func (c *ResetPasswordCommand) UnmarshalEvent(evt event.Event) error {
	c.Token = string(evt.Topic)
	c.Password = string(evt.Topic)
	return nil
}

type ResetPasswordUseCase struct {
	userRepo         port.UserRepository
	refreshTokenRepo port.RefreshTokenRepository
	uow              coreuow.UnitOfWork
	revocationCache  *service.RevocationCache
}

func NewResetPasswordUseCase(deps define.Dependencies) usecase.UseCase {
	return &ResetPasswordUseCase{
		userRepo:         deps.UserRepo,
		refreshTokenRepo: deps.RefreshTokenRepo,
		uow:              deps.UoW,
		revocationCache:  service.NewRevocationCache(deps.Cache),
	}
}

func (uc *ResetPasswordUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*ResetPasswordCommand)

	var userID entity.UserID
	var invalidatedAt time.Time
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
			invalidatedAt = *u.SessionsInvalidatedAt
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

	// Refresh tokens are revoked in Mongo above, but access tokens are stateless — only this
	// marker stops the ones already issued (grant-linkage.md §9).
	if err := uc.revocationCache.MarkSessionsInvalidated(ctx, userID, invalidatedAt); err != nil {
		log.Error().Err(err).Str("user_id", string(userID)).Msg("reset_password: failed to mark sessions invalidated")
	}

	return nil, nil
}
