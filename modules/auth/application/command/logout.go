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
	RefreshToken          *string `cookie:"refresh_token"`
	IDTokenHint           *string `form:"id_token_hint"`
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

	var accessClaims *corejwt.Claims
	if c.AccessToken != nil {
		if claims, err := uc.jwtSvc.ParseJWT(*c.AccessToken); err == nil && claims != nil {
			accessClaims = claims
		}
	}

	if accessClaims != nil {
		uc.blacklistAccessToken(ctx, accessClaims)
	}

	if userID := uc.resolveUserID(ctx, accessClaims, c.IDTokenHint, c.RefreshToken); userID != "" {
		_ = uc.refreshTokenRepo.RevokeAllForUser(ctx, entity.UserID(userID))
	}

	resp := &define.LogoutResponse{}
	if c.PostLogoutRedirectURI != nil && slices.Contains(uc.postLogoutRedirectAllowlist, *c.PostLogoutRedirectURI) {
		resp.RedirectURI = *c.PostLogoutRedirectURI
	}
	return resp, nil
}

// resolveUserID returns the subject of the actor making the logout request.
// Priority: access token (caller-bound) → id_token_hint → refresh_token cookie (repo lookup).
func (uc *LogoutUseCase) resolveUserID(ctx context.Context, accessClaims *corejwt.Claims, idTokenHint, refreshToken *string) string {
	if accessClaims != nil && accessClaims.Subject != "" {
		return accessClaims.Subject
	}
	if idTokenHint != nil {
		if claims, err := uc.jwtSvc.ParseIDToken(*idTokenHint); err == nil && claims != nil {
			return claims.Subject
		}
	}
	if refreshToken != nil {
		if rt, err := uc.refreshTokenRepo.FindByTokenHash(ctx, entity.Hash(*refreshToken)); err == nil && rt != nil && rt.IsValid() {
			return string(rt.UserID)
		}
	}
	return ""
}

func (uc *LogoutUseCase) blacklistAccessToken(ctx context.Context, claims *corejwt.Claims) {
	if claims.ID == "" || claims.IsExpired() {
		return
	}
	if err := uc.cache.Set(ctx, fmt.Sprintf(define.BlacklistCacheKey, claims.ID), true, new(time.Until(*claims.ExpiresAt))); err != nil {
		log.Warn().Err(err).Str("jti", claims.ID).Msg("blacklist: cache set failed")
	}
}
