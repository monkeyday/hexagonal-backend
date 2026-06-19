package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	corecache "sc/core/cache"
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
}

func NewForgotPasswordUseCase(deps define.Dependencies) usecase.UseCase {
	return &ForgotPasswordUseCase{
		userRepo:    deps.UserRepo,
		emailSender: deps.EmailSender,
		cache:       deps.Cache,
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
	// TODO(WS11): replace with a transactional outbox — save the reset token and an
	// outbox message atomically so they succeed and fail together; a relay/worker then
	// delivers the email. Deferred to the WS11 task module (Redis queue + worker).
	if err := uc.userRepo.Save(ctx, &updated); err != nil {
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
