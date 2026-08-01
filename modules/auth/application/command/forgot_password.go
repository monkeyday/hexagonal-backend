package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	corecache "sc/core/cache"
	coreuow "sc/core/uow"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

const (
	forgotPasswordMaxPerWindow = 3
	forgotPasswordWindow       = time.Hour
)

type ForgotPasswordCommand struct {
	Email string `form:"email" json:"email" validate:"required,email"`
}

type ForgotPasswordUseCase struct {
	userRepo    port.UserRepository
	emailSender port.EmailSender
	cache       corecache.Cache
	uow         coreuow.UnitOfWork
}

func NewForgotPasswordUseCase(deps define.Dependencies) usecase.UseCase {
	return &ForgotPasswordUseCase{
		userRepo:    deps.UserRepo,
		emailSender: deps.EmailSender,
		cache:       deps.Cache,
		uow:         deps.UoW,
	}
}

func (uc *ForgotPasswordUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*ForgotPasswordCommand)

	// Per-email throttle: cap reset requests for any one address so the endpoint
	// cannot be used to flood a victim's inbox. The response is identical whether
	// or not the cap is hit, preserving the no-enumeration guarantee.
	if uc.rateLimited(ctx, c.Email) {
		return nil, nil
	}

	user, _ := uc.userRepo.FindByEmail(ctx, entity.DefaultTenantID, c.Email)
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
	if err := uc.persistResetToken(ctx, &updated); err != nil {
		log.Error().Err(err).Msg("forgot_password: failed to save reset token")
		return nil, nil
	}

	if uc.emailSender != nil {
		if err := uc.emailSender.SendPasswordResetEmail(ctx, updated.Email, token); err != nil {
			log.Error().Err(err).Str("user_id", string(updated.ID)).Msg("forgot_password: failed to send reset email")
		}
	}

	return nil, nil
}

// persistResetToken saves the token inside a unit of work. The transaction is
// not needed for this single write — it exists for what joins it next: the
// outbox row carrying the reset email must be written in the same transaction
// as the token, so neither can exist without the other (docs/outbox-module.md).
//
// The email send deliberately stays outside. It is not a database write, so a
// rollback cannot recall it, and WithTransaction re-runs its whole callback on
// a transient error — which would send the mail again on every attempt.
func (uc *ForgotPasswordUseCase) persistResetToken(ctx context.Context, user *entity.User) error {
	_, err := uc.uow.Do(ctx, func(txCtx context.Context) (any, error) {
		return nil, uc.userRepo.Save(txCtx, user)
	})
	return err
}

// rateLimited reports whether this email has exceeded the reset-request cap in
// the current window. A cache failure is best-effort and must not block
// password recovery, so it is treated as not limited.
func (uc *ForgotPasswordUseCase) rateLimited(ctx context.Context, email string) bool {
	if uc.cache == nil {
		return false
	}
	count, err := uc.cache.IncrWindow(ctx, forgotPasswordRateKey(email), forgotPasswordWindow)
	if err != nil {
		log.Error().Err(err).Msg("forgot_password: rate-limit check failed")
		return false
	}
	return count > forgotPasswordMaxPerWindow
}

func forgotPasswordRateKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return fmt.Sprintf(define.ForgotPasswordRateKey, hex.EncodeToString(sum[:]))
}
