package command

import (
	"context"
	"fmt"
	corecache "sc/core/cache"
	corejwt "sc/core/jwt"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
)

type LogoutCommand struct {
	AccessToken           *string `ctx:"access_token"`
	PostLogoutRedirectURI *string `form:"post_logout_redirect_uri"`
}

type LogoutUseCase struct {
	jwtSvc                      port.TokenParser
	cache                       corecache.Cache
	refreshTokenRepo            port.RefreshTokenRepository
	postLogoutRedirectAllowlist []string
}

func NewLogoutUseCase(deps define.Dependencies) usecase.UseCase {
	return &LogoutUseCase{
		jwtSvc:                      deps.JWTSvc,
		cache:                       deps.Cache,
		refreshTokenRepo:            deps.RefreshTokenRepo,
		postLogoutRedirectAllowlist: deps.PostLogoutRedirectAllowlist,
	}
}

func (uc *LogoutUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*LogoutCommand)

	uc.revokeIfAuthenticated(ctx, c.AccessToken)

	resp := &define.LogoutResponse{}
	if c.PostLogoutRedirectURI != nil && slices.Contains(uc.postLogoutRedirectAllowlist, *c.PostLogoutRedirectURI) {
		resp.RedirectURI = *c.PostLogoutRedirectURI
	}
	return resp, nil
}

// revokeIfAuthenticated revokes sessions only for a caller presenting a valid
// bearer access token. id_token_hint or the refresh cookie alone must never
// trigger revocation: both ride along on cross-site GET navigations, which
// would let an attacker log a victim out of everything (CSRF).
func (uc *LogoutUseCase) revokeIfAuthenticated(ctx context.Context, accessToken *string) {
	if accessToken == nil {
		return
	}
	claims, err := uc.jwtSvc.ParseJWT(*accessToken)
	if err != nil || claims == nil {
		return
	}
	uc.blacklistAccessToken(ctx, claims)
	uc.revokeGrantTokens(ctx, claims)
}

// revokeGrantTokens revokes the refresh tokens associated with the caller's session.
// When the access token carries a grant ID (sid claim), only that grant's tokens are
// revoked — logout ends the current session only (grant-linkage.md §1, §5).
// Legacy tokens without a grant ID fall back to revoking all tokens for the user.
// Expand/contract: remove the legacy branch once all sessions carry sid — grant-linkage.md §5.
func (uc *LogoutUseCase) revokeGrantTokens(ctx context.Context, claims *corejwt.Claims) {
	if claims.GrantID != "" {
		_ = uc.refreshTokenRepo.RevokeAllForGrant(ctx, entity.GrantID(claims.GrantID))
		if err := uc.cache.Set(ctx, fmt.Sprintf(define.RevokedGrantCacheKey, claims.GrantID), true, new(define.RevokedGrantMarkerTTL)); err != nil {
			log.Warn().Err(err).Str("grant_id", claims.GrantID).Msg("revoked_grant: cache set failed")
		}
		return
	}
	// Legacy fallback: tokens issued before grant linkage carry no sid; revoke by user.
	if claims.Subject != "" {
		_ = uc.refreshTokenRepo.RevokeAllForUser(ctx, entity.UserID(claims.Subject))
	}
}

func (uc *LogoutUseCase) blacklistAccessToken(ctx context.Context, claims *corejwt.Claims) {
	if claims.ID == "" || claims.IsExpired() {
		return
	}
	if err := uc.cache.Set(ctx, fmt.Sprintf(define.BlacklistCacheKey, claims.ID), true, new(time.Until(*claims.ExpiresAt))); err != nil {
		log.Warn().Err(err).Str("jti", claims.ID).Msg("blacklist: cache set failed")
	}
}
