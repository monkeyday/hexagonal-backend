package command

import (
	"context"
	"errors"
	coreerror "sc/core/error"
	corejwt "sc/core/jwt"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/application/service"
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
	revocationCache             *service.RevocationCache
	refreshTokenRepo            port.RefreshTokenRepository
	grantRepo                   port.GrantRepository
	postLogoutRedirectAllowlist []string
}

func NewLogoutUseCase(deps define.Dependencies) usecase.UseCase {
	return &LogoutUseCase{
		jwtSvc:                      deps.JWTSvc,
		revocationCache:             service.NewRevocationCache(deps.Cache),
		refreshTokenRepo:            deps.RefreshTokenRepo,
		grantRepo:                   deps.GrantRepo,
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
// The grant itself is revoked first: it is the durable record a rotation committing
// mid-sweep cannot escape, and it outlives the cache marker (grant-linkage.md §10).
// Legacy tokens without a grant ID fall back to revoking all tokens for the user.
// Expand/contract: remove the legacy branch once all sessions carry sid — grant-linkage.md §5.
func (uc *LogoutUseCase) revokeGrantTokens(ctx context.Context, claims *corejwt.Claims) {
	if claims.GrantID != "" {
		grantID := entity.GrantID(claims.GrantID)
		uc.revokeGrant(ctx, grantID)
		_ = uc.refreshTokenRepo.RevokeAllForGrant(ctx, grantID)
		if err := uc.revocationCache.MarkGrantRevoked(ctx, grantID); err != nil {
			log.Warn().Err(err).Str("grant_id", claims.GrantID).Msg("revoked_grant: cache set failed")
		}
		return
	}
	// Legacy fallback: tokens issued before grant linkage carry no sid; revoke by user.
	if claims.Subject != "" {
		_ = uc.refreshTokenRepo.RevokeAllForUser(ctx, entity.UserID(claims.Subject))
	}
}

// revokeGrant marks the grant dead before the row sweep runs. ErrNotFound means
// the grant predates this record or a concurrent revocation already won —
// neither is an error. Like the sweep it precedes, this is best-effort: logout
// must not fail because a revocation record could not be written.
func (uc *LogoutUseCase) revokeGrant(ctx context.Context, grantID entity.GrantID) {
	if err := uc.grantRepo.Revoke(ctx, grantID, time.Now()); err != nil && !errors.Is(err, coreerror.ErrNotFound) {
		log.Warn().Err(err).Str("grant_id", string(grantID)).Msg("grant revoke failed on logout")
	}
}

func (uc *LogoutUseCase) blacklistAccessToken(ctx context.Context, claims *corejwt.Claims) {
	if claims.ID == "" || claims.IsExpired() {
		return
	}
	if err := uc.revocationCache.BlacklistJTI(ctx, claims.ID, *claims.ExpiresAt); err != nil {
		log.Warn().Err(err).Str("jti", claims.ID).Msg("blacklist: cache set failed")
	}
}
