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
)

type RefreshTokenCommand struct {
	GrantType    string `form:"grant_type" json:"grant_type" validate:"required"`
	ClientID     string `form:"client_id" json:"client_id" validate:"required"`
	RefreshToken string `form:"refresh_token" json:"refresh_token" cookie:"refresh_token" validate:"required"`
	ExpireSecs   *int   `form:"expire_secs" json:"expire_secs" validate:"omitempty,gt=0"`
}

type RefreshTokenUseCase struct {
	uow                  coreuow.UnitOfWork
	userRepo             port.UserRepository
	refreshTokenRepo     port.RefreshTokenRepository
	tokenIssuanceService *domainService.TokenIssuanceService
}

func NewRefreshTokenUseCase(deps define.Dependencies) usecase.UseCase {
	return &RefreshTokenUseCase{
		uow:                  deps.UoW,
		userRepo:             deps.UserRepo,
		refreshTokenRepo:     deps.RefreshTokenRepo,
		tokenIssuanceService: domainService.NewTokenIssuanceService(deps.JWTSvc),
	}
}

func (uc *RefreshTokenUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*RefreshTokenCommand)

	// TODO: once a client registry exists, verify client_id is registered and allowed to use
	// the refresh_token grant; validate client_secret for confidential clients here.
	rt, err := uc.refreshTokenRepo.FindByTokenHash(ctx, entity.Hash(c.RefreshToken))
	if err != nil || rt == nil || !rt.IsValid() {
		return nil, autherrors.NewErrInvalidRefreshToken()
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
