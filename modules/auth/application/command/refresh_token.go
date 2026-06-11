package command

import (
	"context"
	"errors"

	coreerror "sc/core/error"
	coreuow "sc/core/uow"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	domainService "sc/modules/auth/application/service"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

type RefreshTokenCommand struct {
	GrantType         string `form:"grant_type" json:"grant_type" validate:"required"`
	ClientID          string `form:"client_id" json:"client_id" validate:"required"`
	ClientSecret      string `form:"client_secret" json:"client_secret"`
	BasicClientID     string `ctx:"basic_client_id"`
	BasicClientSecret string `ctx:"basic_client_secret"`
	RefreshToken      string `form:"refresh_token" json:"refresh_token" cookie:"refresh_token" validate:"required"`
	ExpireSecs        *int   `form:"expire_secs" json:"expire_secs" validate:"omitempty,gt=0"`
}

type RefreshTokenUseCase struct {
	uow                  coreuow.UnitOfWork
	userRepo             port.UserRepository
	refreshTokenRepo     port.RefreshTokenRepository
	tokenIssuanceService *domainService.TokenIssuanceService
	clientAuthenticator  *domainService.ClientAuthenticator
}

func NewRefreshTokenUseCase(deps define.Dependencies) usecase.UseCase {
	return &RefreshTokenUseCase{
		uow:                  deps.UoW,
		userRepo:             deps.UserRepo,
		refreshTokenRepo:     deps.RefreshTokenRepo,
		tokenIssuanceService: domainService.NewTokenIssuanceService(deps.JWTSvc),
		clientAuthenticator:  domainService.NewClientAuthenticator(deps.ClientRegistry),
	}
}

func (uc *RefreshTokenUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*RefreshTokenCommand)

	client, err := uc.clientAuthenticator.Authenticate(ctx, domainService.ClientCredentials{
		ClientID:      c.ClientID,
		FormSecret:    c.ClientSecret,
		BasicClientID: c.BasicClientID,
		BasicSecret:   c.BasicClientSecret,
	})
	if err != nil {
		return nil, autherrors.NewErrInvalidClient()
	}
	if !client.AllowsGrant(entity.GrantRefreshToken) {
		return nil, autherrors.NewErrInvalidClient()
	}

	rt, err := uc.findActiveRefreshToken(ctx, c.RefreshToken)
	if err != nil {
		return nil, err
	}

	user, err := uc.userRepo.FindByID(ctx, rt.UserID)
	if err != nil || user == nil {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}

	if user.SessionsInvalidatedAt != nil && !rt.AuthenticatedAt.After(*user.SessionsInvalidatedAt) {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}

	expireSecs := define.ResolveExpirySecs(c.ExpireSecs)

	tokens, err := uc.tokenIssuanceService.IssueTokens(domainService.IssueTokensArgs{
		User:       user,
		ClientID:   entity.ClientID(c.ClientID),
		Scope:      rt.Scope,
		ExpireSecs: expireSecs,
	})
	if err != nil {
		return nil, err
	}

	if err := uc.updateRefreshToken(ctx, rt, user.ID, tokens); err != nil {
		return nil, err
	}

	res := &define.TokenResponse{}
	res.FromEntity(tokens, expireSecs)
	return res, nil
}

// findActiveRefreshToken loads the presented token and enforces reuse
// detection: a revoked token being presented again means it was already
// rotated once — assume theft and revoke the user's whole token family.
// Expired tokens are rejected without consequences; expiry is not evidence
// of theft. Runs outside the rotation transaction on purpose: the family
// revocation must survive the request failing.
func (uc *RefreshTokenUseCase) findActiveRefreshToken(ctx context.Context, raw string) (*entity.RefreshToken, error) {
	rt, err := uc.refreshTokenRepo.FindByTokenHash(ctx, entity.Hash(raw))
	if err != nil || rt == nil {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}
	if rt.RevokedAt != nil {
		log.Warn().Str("user_id", string(rt.UserID)).Msg("refresh token replay detected; revoking all tokens for user")
		if err := uc.refreshTokenRepo.RevokeAllForUser(ctx, rt.UserID); err != nil {
			log.Error().Err(err).Str("user_id", string(rt.UserID)).Msg("failed to revoke token family after replay")
		}
		return nil, autherrors.NewErrInvalidRefreshToken()
	}
	if !rt.IsValid() {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}
	return rt, nil
}

func (uc *RefreshTokenUseCase) updateRefreshToken(ctx context.Context, oldRT *entity.RefreshToken, userID entity.UserID, newTokens *entity.IssuedTokens) error {
	_, err := uc.uow.Do(ctx, func(ctx context.Context) (any, error) {
		if err := uc.refreshTokenRepo.RevokeByTokenHash(ctx, oldRT.TokenHash); err != nil {
			if errors.Is(err, coreerror.ErrNotFound) {
				return nil, autherrors.NewErrInvalidRefreshToken()
			}
			return nil, autherrors.NewErrGenRefreshTokenFailed(err)
		}
		newRT := oldRT.Rotate(userID, newTokens)
		if err := uc.refreshTokenRepo.Save(ctx, newRT); err != nil {
			return nil, autherrors.NewErrGenRefreshTokenFailed(err)
		}
		return nil, nil
	})
	return err
}
