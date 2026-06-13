package command

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	corecache "sc/core/cache"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

type CreateAuthCodeCommand struct {
	Email     string `form:"email"      validate:"required"`
	Password  string `form:"password"   validate:"required"`
	CSRFToken string `form:"csrf_token" validate:"required"`
	SessionID string `cookie:"auth_session" validate:"required"`
}

func (c *CreateAuthCodeCommand) ValidateCSRF(csrfToken string) bool {
	return subtle.ConstantTimeCompare([]byte(c.CSRFToken), []byte(csrfToken)) == 1
}

type CreateAuthCodeUseCase struct {
	userRepo port.UserRepository
	cache    corecache.Cache
}

func NewCreateAuthCodeUseCase(deps define.Dependencies) usecase.UseCase {
	return &CreateAuthCodeUseCase{
		userRepo: deps.UserRepo,
		cache:    deps.Cache,
	}
}

func (uc *CreateAuthCodeUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*CreateAuthCodeCommand)

	sessionKey := fmt.Sprintf(define.AuthorizeRequestCacheKey, c.SessionID)
	var session entity.AuthorizeRequest
	if ok := uc.cache.GetAndDelete(ctx, sessionKey, &session); !ok {
		return nil, autherrors.NewErrInvalidSession()
	}
	if err := session.Validate(); err != nil {
		return nil, autherrors.NewErrInvalidSession()
	}

	if !c.ValidateCSRF(session.CSRFToken) {
		return nil, autherrors.NewErrInvalidSession()
	}

	userID, err := uc.verifyCredentials(ctx, &session, c.Email, c.Password)
	if err != nil {
		return nil, err
	}

	authCode, err := entity.NewAuthCode(entity.AuthCodeArgs{
		UserID:              userID,
		ClientID:            session.ClientID,
		RedirectURI:         session.RedirectURI,
		Scope:               session.Scope,
		Nonce:               session.Nonce,
		CodeChallenge:       session.CodeChallenge,
		CodeChallengeMethod: session.CodeChallengeMethod,
	})
	if err != nil {
		return nil, autherrors.NewErrAuthCodeCreateFailed(err)
	}
	if err := uc.cache.Set(ctx, fmt.Sprintf(define.AuthCodeCacheKey, authCode.Code), authCode, new(entity.AuthCodeTTL)); err != nil {
		return nil, err
	}

	log.Info().Str("user_id", string(userID)).Str("client_id", string(session.ClientID)).Msg("auth code issued")

	return &define.CreateAuthCodeResponse{RedirectURI: session.BuildRedirectURI(authCode.Code)}, nil
}

func (uc *CreateAuthCodeUseCase) verifyCredentials(ctx context.Context, session *entity.AuthorizeRequest, email, password string) (entity.UserID, error) {
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.Is(err, coreerror.ErrNotFound) {
		return "", err
	}

	// Account lockout is checked before password validation and answered with
	// the generic credentials error: a locked account must not become an
	// enumeration oracle, nor confirm that a guessed password was correct.
	if user != nil && user.IsLockedOut() {
		log.Warn().Str("user_id", string(user.ID)).Msg("sign-in rejected: account locked")
		return "", autherrors.NewErrInvalidEmailOrPassword()
	}

	if user == nil || user.ValidatePassword(password) != nil {
		log.Warn().Msg("sign-in failed: invalid credentials")
		uc.recordAccountFailure(ctx, user)

		sessionKey := fmt.Sprintf(define.AuthorizeRequestCacheKey, session.ID)
		session.RequestFail()

		if session.IsLockedOut() {
			return "", autherrors.NewErrMaxLoginAttemptsExceeded()
		}

		if err := uc.cache.Set(ctx, sessionKey, session, new(entity.AuthorizeRequestTTL)); err != nil {
			log.Warn().Err(err).Msg("failed to update session after login failure")
		}

		return "", autherrors.NewErrInvalidEmailOrPassword()
	}

	uc.resetAccountFailures(ctx, user)
	return user.ID, nil
}

func (uc *CreateAuthCodeUseCase) recordAccountFailure(ctx context.Context, user *entity.User) {
	if user == nil {
		return
	}
	user.RecordFailedLogin()
	if err := uc.userRepo.Save(ctx, user); err != nil {
		log.Warn().Err(err).Str("user_id", string(user.ID)).Msg("failed to persist account login failure")
	}
}

func (uc *CreateAuthCodeUseCase) resetAccountFailures(ctx context.Context, user *entity.User) {
	if user.FailedLoginAttempts == 0 && user.LockedUntil == nil {
		return
	}
	user.ResetFailedLogins()
	if err := uc.userRepo.Save(ctx, user); err != nil {
		log.Warn().Err(err).Str("user_id", string(user.ID)).Msg("failed to reset account login failures")
	}
}
