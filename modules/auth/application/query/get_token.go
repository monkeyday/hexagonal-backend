package query

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/application/service"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

type GetTokenQuery struct {
	Email      string  `form:"email" json:"email" validate:"required,email"`
	Password   string  `form:"password" json:"password" validate:"required"`
	Scope      *string `form:"scope" json:"scope"`
	ExpireSecs *int    `form:"expire_secs" json:"expire_secs" validate:"omitempty,gte=0"`
}

// GetTokenUseCase implements the password grant (grant_type=password).
// Intentional: kept for internal/trusted service use where the authorization code flow is not applicable.
// Deprecated in OAuth 2.1; do not expose to public or browser-based clients.
type GetTokenUseCase struct {
	userRepo             port.UserRepository
	refreshTokenRepo     port.RefreshTokenRepository
	tokenIssuanceService *service.TokenIssuanceService
	scopeAllowlist       []string
}

func NewGetTokenUseCase(deps define.Dependencies) usecase.UseCase {
	return &GetTokenUseCase{
		userRepo:             deps.UserRepo,
		refreshTokenRepo:     deps.RefreshTokenRepo,
		tokenIssuanceService: service.NewTokenIssuanceService(deps.JWTSvc),
		scopeAllowlist:       deps.ScopeAllowlist,
	}
}

func (uc *GetTokenUseCase) Execute(ctx context.Context, query any) (any, error) {
	q := query.(*GetTokenQuery)

	user, err := uc.userRepo.FindByEmail(ctx, q.Email)
	if err != nil || user == nil {
		log.Warn().Str("email", q.Email).Msg("user not found")
		return nil, autherrors.NewErrInvalidEmailOrPassword()
	}

	if err := user.ValidatePassword(q.Password); err != nil {
		log.Warn().Str("email", q.Email).Msg("password not matched")
		return nil, autherrors.NewErrInvalidEmailOrPassword()
	}

	scope, err := uc.resolveScope(q.Scope)
	if err != nil {
		return nil, err
	}

	expireSecs := define.ResolveExpirySecs(q.ExpireSecs)

	tokens, err := uc.tokenIssuanceService.IssueTokens(service.IssueTokensArgs{
		User:       user,
		Scope:      scope,
		ExpireSecs: expireSecs,
	})
	if err != nil {
		return nil, err
	}

	rt := entity.NewRefreshToken(user.ID, tokens)
	if err := uc.refreshTokenRepo.Save(ctx, rt); err != nil {
		return nil, coreerror.NewErr(autherrors.GenTokenFailed, err)
	}

	log.Info().Str("user_id", string(user.ID)).Msg("password grant: tokens issued")
	res := &define.TokenResponse{}
	res.FromEntity(tokens, expireSecs)
	return res, nil
}

func (uc *GetTokenUseCase) resolveScope(requested *string) (entity.Scope, error) {
	if requested == nil || *requested == "" {
		scope, _ := entity.NewScope(uc.scopeAllowlist) // allowlist is validated at startup
		return scope, nil
	}
	for _, s := range strings.Fields(*requested) {
		if !slices.Contains(uc.scopeAllowlist, s) {
			return entity.Scope{}, coreerror.NewErr(autherrors.InvalidArguments, errors.New("invalid scope: "+s))
		}
	}
	return entity.NewScope(strings.Fields(*requested))
}
