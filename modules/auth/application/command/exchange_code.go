package command

import (
	"context"
	"errors"
	"fmt"
	corecache "sc/core/cache"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/application/service"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

type ExchangeCodeCommand struct {
	Code         string `form:"code"          validate:"required"`
	ClientID     string `form:"client_id"     validate:"required"`
	RedirectURI  string `form:"redirect_uri"  validate:"required,redirect_uri"`
	ExpireSecs   *int   `form:"expire_secs"   validate:"omitempty,gt=0"`
	CodeVerifier string `form:"code_verifier"`
	// TODO: add DeviceID field and pass it to NewRefreshToken once client support is established
}

type ExchangeCodeUseCase struct {
	userRepo             port.UserRepository
	refreshTokenRepo     port.RefreshTokenRepository
	cache                corecache.Cache
	tokenIssuanceService *service.TokenIssuanceService
}

func NewExchangeCodeUseCase(deps define.Dependencies) usecase.UseCase {
	return &ExchangeCodeUseCase{
		userRepo:             deps.UserRepo,
		refreshTokenRepo:     deps.RefreshTokenRepo,
		cache:                deps.Cache,
		tokenIssuanceService: service.NewTokenIssuanceService(deps.JWTSvc),
	}
}

func (uc *ExchangeCodeUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*ExchangeCodeCommand)

	authCode, err := uc.consumeAuthCode(ctx, c.Code)
	if err != nil || authCode == nil {
		return nil, autherrors.NewErrAuthCodeNotFound()
	}

	// TODO: once a client registry exists, verify client is registered and allowed to use
	if !authCode.IsValid(c.ClientID, c.RedirectURI, c.CodeVerifier) {
		return nil, autherrors.NewErrInvalidGrant()
	}

	user, err := uc.userRepo.FindByID(ctx, authCode.UserID)
	if err != nil {
		return nil, err
	}

	expireSecs := define.ResolveExpirySecs(c.ExpireSecs)

	tokens, err := uc.issueTokens(c.ClientID, expireSecs, authCode, user)
	if err != nil {
		return nil, err
	}

	if err := uc.saveRefreshToken(ctx, user.ID, tokens); err != nil {
		return nil, err
	}

	log.Info().Str("user_id", string(user.ID)).Str("client_id", c.ClientID).Msg("code exchanged for tokens")

	res := &define.TokenResponse{}
	res.FromEntity(tokens, expireSecs)
	return res, nil
}

func (uc *ExchangeCodeUseCase) issueTokens(clientID string, expireSecs int, authCode *entity.AuthCode, user *entity.User) (*entity.IssuedTokens, error) {
	nonce := ""
	if authCode.Nonce != nil {
		nonce = *authCode.Nonce
	}

	return uc.tokenIssuanceService.IssueTokens(service.IssueTokensArgs{
		User:       user,
		ClientID:   entity.ClientID(clientID),
		Nonce:      nonce,
		Scope:      authCode.Scope,
		ExpireSecs: expireSecs,
	})
}

func (uc *ExchangeCodeUseCase) saveRefreshToken(ctx context.Context, userID entity.UserID, tokens *entity.IssuedTokens) error {
	rt := entity.NewRefreshToken(userID, tokens)
	return uc.refreshTokenRepo.Save(ctx, rt)
}

func (uc *ExchangeCodeUseCase) consumeAuthCode(ctx context.Context, code string) (*entity.AuthCode, error) {
	var ac entity.AuthCode
	if ok := uc.cache.GetAndDelete(ctx, fmt.Sprintf(define.AuthCodeCacheKey, code), &ac); !ok {
		return nil, errors.New("auth code not found")
	}
	if err := ac.Validate(); err != nil {
		return nil, errors.New("auth code not found")
	}
	return &ac, nil
}
