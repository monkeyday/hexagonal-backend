package command

import (
	"context"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

type ForgotPasswordCommand struct {
	Email string `form:"email" json:"email" validate:"required,email"`
}

type ForgotPasswordUseCase struct {
	userRepo    port.UserRepository
	emailSender port.EmailSender
}

func NewForgotPasswordUseCase(deps define.Dependencies) usecase.UseCase {
	return &ForgotPasswordUseCase{
		userRepo:    deps.UserRepo,
		emailSender: deps.EmailSender,
	}
}

func (uc *ForgotPasswordUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*ForgotPasswordCommand)

	user, _ := uc.userRepo.FindByEmail(ctx, c.Email)
	if user == nil {
		return nil, nil
	}

	token, err := entity.GeneratePasswordResetToken()
	if err != nil {
		log.Error().Err(err).Msg("forgot_password: token generation failed")
		return nil, nil
	}

	updated := *user
	updated.SetPasswordResetToken(token, entity.PasswordResetTokenTTL)
	// TODO: replace with transactional outbox — save token and outbox message atomically so
	// they succeed and fail together.
	if err := uc.userRepo.Save(ctx, &updated); err != nil {
		log.Error().Err(err).Msg("forgot_password: failed to save reset token")
		return nil, nil
	}

	if uc.emailSender != nil {
		if err := uc.emailSender.SendPasswordResetEmail(ctx, updated.Email, token); err != nil {
			log.Error().Err(err).Str("email", updated.Email).Msg("forgot_password: failed to send reset email")
		}
	}

	return nil, nil
}
